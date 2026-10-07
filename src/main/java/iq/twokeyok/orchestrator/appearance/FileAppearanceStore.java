package iq.twokeyok.orchestrator.appearance;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * One JSON file per {@code template_id} in {@code appearance.store-path}. The
 * API and the directory are the same store, deliberately, so an operator can
 * inspect, back up and hand-edit what callers have created.
 */
public class FileAppearanceStore implements AppearanceStore {

    private static final Logger log = LoggerFactory.getLogger(FileAppearanceStore.class);

    private final String storePath;
    private final ObjectMapper objectMapper;

    public FileAppearanceStore(String storePath, ObjectMapper objectMapper) {
        this.storePath = storePath;
        this.objectMapper = objectMapper;
    }

    @Override
    public List<AppearanceTemplate> loadAll() {
        if (!isWritable()) {
            return List.of();
        }
        Path directory = Path.of(storePath);
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

    @Override
    public void save(AppearanceTemplate template) {
        Path file = file(template.templateId());
        try {
            Files.createDirectories(file.getParent());
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), template);
        } catch (IOException e) {
            log.error("Cannot write appearance template {}: {}", file, e.getMessage());
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_WRITTEN, e, template.templateId());
        }
    }

    @Override
    public void delete(String templateId) {
        try {
            Files.deleteIfExists(file(templateId));
        } catch (IOException e) {
            log.error("Cannot delete appearance template {}: {}", templateId, e.getMessage());
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_WRITTEN, e, templateId);
        }
    }

    @Override
    public boolean isWritable() {
        return storePath != null && !storePath.isBlank();
    }

    @Override
    public String describe() {
        return storePath;
    }

    /** The id has already been checked against a safe character set by the repository. */
    private Path file(String templateId) {
        return Path.of(storePath).toAbsolutePath().normalize().resolve(templateId + ".json");
    }
}
