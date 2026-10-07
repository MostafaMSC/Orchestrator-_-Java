package iq.twokeyok.orchestrator.appearance;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.TestProperties;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The appearance store over a table defined exactly as the Ascertia
 * Orchestrator defines it in PostgreSQL:
 * {@code template_id varchar(255) PRIMARY KEY, signatureappearance text}.
 */
class JdbcAppearanceStoreTest {

    private static final String ROW = "{\"template_id\":\"Test\",\"enabled\":true,"
            + "\"signed_by\":{\"label\":\"By\",\"value\":\"Lab\",\"enabled\":true,\"include_label\":true},"
            + "\"signature_field\":{\"x\":10,\"y\":20,\"width\":200,\"height\":80,\"page_no\":1}}";

    private final ObjectMapper mapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    private final AscertiaAppearanceCodec codec = new AscertiaAppearanceCodec(mapper);
    private JdbcDataSource dataSource;
    private JdbcAppearanceStore store;

    @BeforeEach
    void createTable() throws Exception {
        dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE TABLE appearancetemplate (template_id VARCHAR(255) NOT NULL PRIMARY KEY, "
                    + "signatureappearance TEXT)");
        }
        store = new JdbcAppearanceStore(dataSource, codec, "appearancetemplate", 30, "test table");
    }

    @Test
    void readsTheRowsTheAscertiaOrchestratorWrote() throws Exception {
        insert("Test", ROW);

        List<AppearanceTemplate> templates = store.loadAll();

        assertThat(templates).extracting(AppearanceTemplate::templateId).containsExactly("Test");
        assertThat(templates.get(0).fields().get(Fields.SIGNED_BY).value()).isEqualTo("Lab");
    }

    @Test
    void skipsARowThatCannotBeReadButKeepsTheOthers() throws Exception {
        insert("Test", ROW);
        insert("broken", "{not json");

        assertThat(store.loadAll()).extracting(AppearanceTemplate::templateId).containsExactly("Test");
    }

    @Test
    void insertsThenUpdatesInTheAscertiaShape() throws Exception {
        AppearanceTemplate template = codec.fromJson(ROW);
        store.save(template);
        store.save(codec.fromJson(ROW.replace("\"Lab\"", "\"Changed\"")));

        assertThat(count()).isEqualTo(1);
        String stored = stored("Test");
        assertThat(mapper.readTree(stored).path("signed_by").path("value").asText()).isEqualTo("Changed");
        assertThat(mapper.readTree(stored).has("fields")).isFalse();
    }

    @Test
    void deletesARow() throws Exception {
        insert("Test", ROW);
        store.delete("Test");

        assertThat(count()).isZero();
    }

    @Test
    void importsOnlyIntoAnEmptyTable() throws Exception {
        AppearanceTemplate fromFile = codec.fromJson(ROW.replace("\"Test\"", "\"from_file\""));

        assertThat(store.importIfEmpty(List.of(fromFile))).isEqualTo(1);
        assertThat(store.importIfEmpty(List.of(codec.fromJson(ROW)))).as("table no longer empty").isZero();
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void refusesATableNameThatIsNotAnIdentifier() {
        assertThatThrownBy(() -> new JdbcAppearanceStore(dataSource, codec, "t; DROP TABLE x", 30, "x"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void backsTheCatalogueAlongsideTheConfiguredTemplates() throws Exception {
        insert("Test", ROW);
        AppearanceRepository repository = new AppearanceRepository(TestProperties.signing(Map.of(
                "signing.dss.signature.appearance.appearances[0].template_id", "from_config",
                "signing.dss.signature.appearance.appearances[0].enabled", "true")),
                mapper, store);

        assertThat(repository.findAll()).extracting(AppearanceTemplate::templateId)
                .containsExactlyInAnyOrder("from_config", "Test");
        assertThat(repository.isManaged("Test")).isTrue();
        assertThat(repository.isManaged("from_config")).isFalse();

        assertThat(repository.save(codec.fromJson(ROW.replace("\"Test\"", "\"new_one\"")))).isTrue();
        assertThat(stored("new_one")).isNotNull();
        assertThatThrownBy(() -> repository.save(codec.fromJson(ROW.replace("\"Test\"", "\"from_config\""))))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.APPEARANCE_READ_ONLY);
    }

    private void insert(String id, String json) throws Exception {
        try (Connection c = dataSource.getConnection();
             PreparedStatement s = c.prepareStatement("INSERT INTO appearancetemplate VALUES (?, ?)")) {
            s.setString(1, id);
            s.setString(2, json);
            s.executeUpdate();
        }
    }

    private long count() throws Exception {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement();
             ResultSet r = s.executeQuery("SELECT COUNT(*) FROM appearancetemplate")) {
            r.next();
            return r.getLong(1);
        }
    }

    private String stored(String id) throws Exception {
        try (Connection c = dataSource.getConnection();
             PreparedStatement s = c.prepareStatement(
                     "SELECT signatureappearance FROM appearancetemplate WHERE template_id = ?")) {
            s.setString(1, id);
            try (ResultSet r = s.executeQuery()) {
                return r.next() ? r.getString(1) : null;
            }
        }
    }
}
