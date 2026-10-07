package iq.twokeyok.orchestrator.appearance;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.sql.DataSource;

import com.fasterxml.jackson.core.JsonProcessingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * The Ascertia Orchestrator's appearance table:
 * {@code template_id varchar PRIMARY KEY, signatureappearance text}.
 *
 * <p>Rows are written in the Ascertia JSON shape ({@link AscertiaAppearanceCodec})
 * so both orchestrators read each other's templates. The table belongs to the
 * Ascertia installation; nothing here creates or alters it.</p>
 *
 * <p>The SQL is plain and portable on purpose: an upsert is an UPDATE followed by
 * an INSERT when nothing was updated, retried once if another writer inserted the
 * same id in between.</p>
 */
public class JdbcAppearanceStore implements AppearanceStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcAppearanceStore.class);
    /** The table name is spliced into SQL, so it is held to an identifier. */
    private static final Pattern TABLE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?");
    private static final String UNIQUE_VIOLATION = "23505";

    private final DataSource dataSource;
    private final AscertiaAppearanceCodec codec;
    private final String table;
    private final int refreshSeconds;
    private final String description;

    public JdbcAppearanceStore(DataSource dataSource, AscertiaAppearanceCodec codec, String table,
                               int refreshSeconds, String description) {
        if (table == null || !TABLE.matcher(table).matches()) {
            throw new IllegalStateException("signing.dss.signature.appearance.jdbc.table is not a valid "
                    + "table name: " + table);
        }
        this.dataSource = dataSource;
        this.codec = codec;
        this.table = table;
        this.refreshSeconds = Math.max(0, refreshSeconds);
        this.description = description;
    }

    @Override
    public List<AppearanceTemplate> loadAll() {
        String sql = "SELECT template_id, signatureappearance FROM " + table + " ORDER BY template_id";
        List<AppearanceTemplate> result = new ArrayList<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                String id = rows.getString(1);
                String json = rows.getString(2);
                if (json == null || json.isBlank()) {
                    log.warn("Appearance row '{}' in {} is empty; skipped", id, table);
                    continue;
                }
                try {
                    AppearanceTemplate template = codec.fromJson(json);
                    // The key column is the identity; a body that disagrees is
                    // reported rather than silently trusted.
                    if (template.templateId() == null || !template.templateId().equals(id)) {
                        log.warn("Appearance row '{}' carries template_id '{}'; using the row key",
                                id, template.templateId());
                        template = withId(template, id);
                    }
                    result.add(template);
                } catch (JsonProcessingException | RuntimeException e) {
                    log.error("Appearance row '{}' in {} cannot be read: {}", id, table, e.getMessage());
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Cannot read appearance templates from " + description
                    + ": " + e.getMessage(), e);
        }
        return result;
    }

    @Override
    public void save(AppearanceTemplate template) {
        String json;
        try {
            json = codec.toJson(template);
        } catch (JsonProcessingException e) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_WRITTEN, e, template.templateId());
        }
        try {
            upsert(template.templateId(), json, true);
        } catch (SQLException e) {
            log.error("Cannot store appearance template '{}' in {}: {}", template.templateId(), description,
                    e.getMessage());
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_WRITTEN, e, template.templateId());
        }
    }

    private void upsert(String id, String json, boolean retry) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement update = connection.prepareStatement(
                    "UPDATE " + table + " SET signatureappearance = ? WHERE template_id = ?")) {
                update.setString(1, json);
                update.setString(2, id);
                if (update.executeUpdate() == 0) {
                    try (PreparedStatement insert = connection.prepareStatement(
                            "INSERT INTO " + table + " (template_id, signatureappearance) VALUES (?, ?)")) {
                        insert.setString(1, id);
                        insert.setString(2, json);
                        insert.executeUpdate();
                    }
                }
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                // Another writer inserted the same id between our UPDATE and
                // INSERT; the row now exists, so updating it is what was meant.
                if (retry && UNIQUE_VIOLATION.equals(e.getSQLState())) {
                    upsert(id, json, false);
                    return;
                }
                throw e;
            }
        }
    }

    @Override
    public void delete(String templateId) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM " + table + " WHERE template_id = ?")) {
            statement.setString(1, templateId);
            statement.executeUpdate();
        } catch (SQLException e) {
            log.error("Cannot delete appearance template '{}' from {}: {}", templateId, description, e.getMessage());
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_WRITTEN, e, templateId);
        }
    }

    /** Copies templates into the table once, while it holds no rows at all. */
    public int importIfEmpty(List<AppearanceTemplate> templates) {
        if (templates.isEmpty()) {
            return 0;
        }
        try (Connection connection = dataSource.getConnection();
             PreparedStatement count = connection.prepareStatement("SELECT COUNT(*) FROM " + table);
             ResultSet rows = count.executeQuery()) {
            rows.next();
            if (rows.getLong(1) > 0) {
                return 0;
            }
        } catch (SQLException e) {
            log.error("Cannot check whether {} is empty; skipping the import: {}", description, e.getMessage());
            return 0;
        }
        int imported = 0;
        for (AppearanceTemplate template : templates) {
            try {
                save(template);
                imported++;
            } catch (OrchestratorException e) {
                log.error("Import of appearance template '{}' failed: {}", template.templateId(), e.getMessage());
            }
        }
        return imported;
    }

    @Override
    public boolean isWritable() {
        return true;
    }

    @Override
    public int refreshSeconds() {
        return refreshSeconds;
    }

    @Override
    public String describe() {
        return description;
    }

    private static AppearanceTemplate withId(AppearanceTemplate t, String id) {
        return new AppearanceTemplate(id, t.name(), t.description(), t.enabled(), t.width(), t.height(),
                t.border(), t.backgroundColor(), t.textFont(), t.signatureField(), t.fields(), null, null);
    }
}
