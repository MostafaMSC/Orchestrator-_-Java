package iq.twokeyok.orchestrator.appearance;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Repository;

import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.AppearanceTemplateConfig;

/**
 * The signature appearance catalogue, assembled from two sources.
 *
 * <ol>
 *   <li>{@code signing.dss.signature.appearance.appearances} — the shape used by
 *       the deployed Ascertia Orchestrator. Text is laid out automatically from
 *       {@code signature_text_position}, and images are read from disk at
 *       start-up.</li>
 *   <li>An optional directory of JSON templates ({@code appearance.store-path}),
 *       for templates that need a box per field or carry embedded images.</li>
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
    private final Path configDir;

    private volatile Map<String, AppearanceTemplate> templates = Map.of();

    public AppearanceRepository(SigningProperties properties, ObjectMapper objectMapper) {
        this.config = properties.dss().signature().appearance();
        this.objectMapper = objectMapper;
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
        if (config.reloadAlways()) {
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
        for (AppearanceTemplate stored : readFromStore()) {
            register(loaded, stored, config.storePath());
        }
        if (loaded.isEmpty()) {
            for (AppearanceTemplate bundled : readBundled()) {
                register(loaded, bundled, "classpath:appearances");
            }
        }

        this.templates = Map.copyOf(loaded);
        log.info("Loaded {} signature appearance template(s): {}", templates.size(), templates.keySet());
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

    private List<AppearanceTemplate> readFromStore() {
        if (config.storePath() == null || config.storePath().isBlank()) {
            return List.of();
        }
        Path directory = Path.of(config.storePath());
        if (!Files.isDirectory(directory)) {
            log.info("Appearance store '{}' does not exist; using the configured templates only", directory);
            return List.of();
        }
        List<AppearanceTemplate> result = new ArrayList<>();
        try (Stream<Path> files = Files.list(directory)) {
            files.filter(path -> path.getFileName().toString().endsWith(".json"))
                    .sorted()
                    .forEach(path -> {
                        try (InputStream in = Files.newInputStream(path)) {
                            result.add(objectMapper.readValue(in, AppearanceTemplate.class));
                        } catch (IOException e) {
                            log.error("Cannot read appearance template {}: {}", path, e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.error("Cannot list appearance store {}: {}", directory, e.getMessage());
        }
        return result;
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
