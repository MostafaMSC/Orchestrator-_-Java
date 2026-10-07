package iq.twokeyok.orchestrator.appearance;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Repository;

import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.AppearanceTemplateConfig;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * The signature appearance catalogue, assembled from two sources.
 *
 * <ol>
 *   <li>{@code signing.dss.signature.appearance.appearances} — the shape used by
 *       the deployed Ascertia Orchestrator. Text is laid out automatically from
 *       {@code signature_text_position}, and images are read from disk at
 *       start-up.</li>
 *   <li>The {@link AppearanceStore} holding templates created through the API:
 *       a directory of JSON files, or the Ascertia Orchestrator's database
 *       table ({@code appearance.store}).</li>
 * </ol>
 *
 * <p>Configuration wins on a clash, because that is the file an operator edits.
 * If neither source yields anything, the templates packaged in the jar are used
 * so a fresh install still answers {@code appearances/list}.</p>
 */
@Repository
public class AppearanceRepository {

    private static final Logger log = LoggerFactory.getLogger(AppearanceRepository.class);
    private static final String BUNDLED_PATTERN = "classpath*:appearances/*.json";

    private final SigningProperties.Appearance config;
    private final ObjectMapper objectMapper;
    private final AppearanceStore store;
    private final Path configDir;

    private volatile Map<String, AppearanceTemplate> templates = Map.of();
    /**
     * Which templates came from the writable store, and so may be changed through
     * the API. A template declared in {@code orchestrator.yml} belongs to whoever
     * edits that file; overwriting it here would be undone at the next restart,
     * so those are refused rather than silently lost.
     */
    private volatile Set<String> managed = Set.of();
    /** Kept so a store that cannot be read for a moment does not empty the catalogue. */
    private volatile List<AppearanceTemplate> lastStored = List.of();
    private volatile long loadedAt;

    /** File store under {@code appearance.store-path}; used where no store bean exists. */
    public AppearanceRepository(SigningProperties properties, ObjectMapper objectMapper) {
        this(properties, objectMapper, new FileAppearanceStore(
                properties.dss().signature().appearance().storePath(), objectMapper));
    }

    @Autowired
    public AppearanceRepository(SigningProperties properties, ObjectMapper objectMapper, AppearanceStore store) {
        this.config = properties.dss().signature().appearance();
        this.objectMapper = objectMapper;
        this.store = store;
        this.configDir = resolveConfigDir(config.storePath());
        reload();
    }

    public Collection<AppearanceTemplate> findAll() {
        return current().values();
    }

    public Optional<AppearanceTemplate> findById(String templateId) {
        if (templateId == null || templateId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(current().get(templateId));
    }

    /** The template used when a request names none and {@code use_default} is on. */
    public Optional<AppearanceTemplate> findDefault() {
        if (!config.useDefault()) {
            return Optional.empty();
        }
        return current().values().stream().filter(AppearanceTemplate::isEnabled).findFirst();
    }

    public boolean isEnabled() {
        return config.enabled();
    }

    private Map<String, AppearanceTemplate> current() {
        int refresh = store.refreshSeconds();
        if (config.reloadAlways()
                || (refresh > 0 && System.currentTimeMillis() - loadedAt > refresh * 1000L)) {
            reload();
        }
        return templates;
    }

    /** Re-reads both sources. Safe at runtime; the swap is atomic. */
    public final synchronized void reload() {
        Map<String, AppearanceTemplate> loaded = new LinkedHashMap<>();

        for (AppearanceTemplateConfig declared : config.appearances()) {
            if (declared.templateId() == null || declared.templateId().isBlank()) {
                log.warn("Ignoring an appearance declared without template_id");
                continue;
            }
            register(loaded, AppearanceLayout.toTemplate(declared, configDir), "configuration");
        }

        List<AppearanceTemplate> stored;
        try {
            stored = store.loadAll();
            lastStored = stored;
        } catch (RuntimeException e) {
            log.error("Cannot read the appearance store ({}); keeping the {} template(s) loaded before: {}",
                    store.describe(), lastStored.size(), e.getMessage());
            stored = lastStored;
        }
        Set<String> fromStore = new LinkedHashSet<>();
        for (AppearanceTemplate template : stored) {
            int before = loaded.size();
            register(loaded, template, store.describe());
            if (loaded.size() > before) {
                fromStore.add(template.templateId());
            }
        }
        if (loaded.isEmpty()) {
            for (AppearanceTemplate bundled : readBundled()) {
                register(loaded, bundled, "classpath:appearances");
            }
        }

        boolean changed = !loaded.keySet().equals(templates.keySet());
        this.templates = Map.copyOf(loaded);
        this.managed = Set.copyOf(fromStore);
        this.loadedAt = System.currentTimeMillis();
        // A database store is re-read every few seconds; say so only when the
        // catalogue actually changed.
        if (changed) {
            log.info("Loaded {} signature appearance template(s): {}", loaded.size(), loaded.keySet());
        }
    }

    // ------------------------------------------------------------------
    // Management, for the appearance CRUD endpoints
    // ------------------------------------------------------------------

    /** {@code true} when a store is configured, so templates can be written. */
    public boolean isWritable() {
        return store.isWritable();
    }

    /** {@code true} when this template lives in the store rather than the configuration. */
    public boolean isManaged(String templateId) {
        return templateId != null && managed.contains(templateId);
    }

    /**
     * Writes a template to the store and reloads the catalogue.
     *
     * @return {@code true} when the template did not exist before
     */
    public synchronized boolean save(AppearanceTemplate template) {
        requireWritableStore();
        String templateId = requireSafeId(template.templateId());
        boolean existed = findById(templateId).isPresent();
        if (existed && !isManaged(templateId)) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_READ_ONLY, templateId);
        }
        store.save(template);
        reload();
        log.info("Appearance template '{}' {} in {}", templateId, existed ? "updated" : "created",
                store.describe());
        return !existed;
    }

    /** Removes a stored template. Configuration-declared templates are refused. */
    public synchronized void delete(String templateId) {
        requireWritableStore();
        requireSafeId(templateId);
        if (findById(templateId).isEmpty()) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_FOUND, templateId);
        }
        if (!isManaged(templateId)) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_READ_ONLY, templateId);
        }
        store.delete(templateId);
        reload();
        log.info("Appearance template '{}' deleted from {}", templateId, store.describe());
    }

    private void requireWritableStore() {
        if (!isWritable()) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_STORE_UNAVAILABLE);
        }
    }

    /**
     * {@code template_id} reaches the store from a request, so it is checked
     * against a conservative character set: anything else could escape the store
     * directory or collide on a case-insensitive filesystem.
     */
    private static String requireSafeId(String templateId) {
        if (templateId == null || templateId.isBlank() || !templateId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_ID_REQUIRED);
        }
        return templateId;
    }

    private static void register(Map<String, AppearanceTemplate> target, AppearanceTemplate template, String origin) {
        if (template.templateId() == null || template.templateId().isBlank()) {
            log.warn("Ignoring appearance template without template_id from {}", origin);
            return;
        }
        if (target.putIfAbsent(template.templateId(), template) != null) {
            log.warn("Appearance template_id '{}' from {} is already defined; keeping the earlier one",
                    template.templateId(), origin);
        }
    }

    /** Relative image paths in the configuration resolve against the store directory. */
    private static Path resolveConfigDir(String storePath) {
        if (storePath == null || storePath.isBlank()) {
            return Path.of(".").toAbsolutePath().normalize();
        }
        return Path.of(storePath).toAbsolutePath().normalize();
    }

    private List<AppearanceTemplate> readBundled() {
        List<AppearanceTemplate> result = new ArrayList<>();
        try {
            Resource[] resources = new PathMatchingResourcePatternResolver().getResources(BUNDLED_PATTERN);
            for (Resource resource : resources) {
                try (InputStream in = resource.getInputStream()) {
                    result.add(objectMapper.readValue(in, AppearanceTemplate.class));
                } catch (IOException e) {
                    log.error("Cannot read bundled appearance {}: {}", resource, e.getMessage());
                }
            }
        } catch (IOException e) {
            log.error("Cannot list bundled appearance templates: {}", e.getMessage());
        }
        return result;
    }
}
