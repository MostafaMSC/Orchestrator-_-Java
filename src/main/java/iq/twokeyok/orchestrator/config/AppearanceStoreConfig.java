package iq.twokeyok.orchestrator.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import iq.twokeyok.orchestrator.appearance.AppearanceStore;
import iq.twokeyok.orchestrator.appearance.AscertiaAppearanceCodec;
import iq.twokeyok.orchestrator.appearance.FileAppearanceStore;
import iq.twokeyok.orchestrator.appearance.JdbcAppearanceStore;

/**
 * Chooses where API-managed appearance templates live, from
 * {@code signing.dss.signature.appearance.store}.
 *
 * <p>The connection pool exists only under {@code store: jdbc}, so a
 * file-based deployment needs no database and starts exactly as before. The
 * pool does not insist on the database at start-up either: signing never
 * depends on it, and the catalogue fills in once the database answers.</p>
 */
@Configuration
public class AppearanceStoreConfig {

    private static final Logger log = LoggerFactory.getLogger(AppearanceStoreConfig.class);

    private HikariDataSource dataSource;

    @Bean
    AppearanceStore appearanceStore(SigningProperties properties, ObjectMapper objectMapper,
                                    AscertiaAppearanceCodec codec) {
        SigningProperties.Appearance appearance = properties.dss().signature().appearance();
        FileAppearanceStore files = new FileAppearanceStore(appearance.storePath(), objectMapper);
        if (!appearance.usesJdbc()) {
            return files;
        }

        SigningProperties.AppearanceJdbc jdbc = appearance.jdbc();
        if (jdbc.url() == null || jdbc.url().isBlank()) {
            throw new IllegalStateException("signing.dss.signature.appearance.store is jdbc but "
                    + "signing.dss.signature.appearance.jdbc.url is not set");
        }
        HikariConfig pool = new HikariConfig();
        pool.setPoolName("appearance-db");
        pool.setJdbcUrl(jdbc.url());
        pool.setUsername(jdbc.username());
        pool.setPassword(jdbc.password());
        pool.setMaximumPoolSize(Math.max(1, jdbc.maxPoolSize()));
        pool.setMinimumIdle(1);
        pool.setConnectionTimeout(5_000);
        // Start even while the database is down; templates appear on the next refresh.
        pool.setInitializationFailTimeout(-1);
        dataSource = new HikariDataSource(pool);

        String description = jdbc.table() + " at " + jdbc.url();
        JdbcAppearanceStore store = new JdbcAppearanceStore(dataSource, codec, jdbc.table(),
                jdbc.refreshSeconds(), description);
        log.info("Appearance templates are stored in {}", description);

        if (jdbc.importFromStorePath()) {
            int imported = store.importIfEmpty(files.loadAll());
            if (imported > 0) {
                log.info("Imported {} appearance template(s) from {} into {}",
                        imported, appearance.storePath(), description);
            }
        }
        return store;
    }

    @jakarta.annotation.PreDestroy
    void closePool() {
        if (dataSource != null) {
            dataSource.close();
        }
    }
}
