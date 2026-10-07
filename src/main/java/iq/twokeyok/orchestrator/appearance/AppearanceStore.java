package iq.twokeyok.orchestrator.appearance;

import java.util.List;

/**
 * Where templates created through the appearance API are kept. Templates
 * declared in {@code orchestrator.yml} never live here.
 */
public interface AppearanceStore {

    /**
     * @throws RuntimeException when the store cannot be read at all; the
     *                          repository then keeps what it loaded last
     */
    List<AppearanceTemplate> loadAll();

    void save(AppearanceTemplate template);

    void delete(String templateId);

    /** {@code false} when nothing is configured to write to. */
    boolean isWritable();

    /**
     * Seconds after which the catalogue is re-read so changes made elsewhere
     * appear; {@code 0} when only this process writes to the store.
     */
    default int refreshSeconds() {
        return 0;
    }

    /** For log lines: where the templates are. */
    String describe();
}
