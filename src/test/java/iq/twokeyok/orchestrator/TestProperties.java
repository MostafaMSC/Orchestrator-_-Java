package iq.twokeyok.orchestrator;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.config.SigningProperties;

/**
 * Binds the configuration records from a flat map exactly as Spring binds
 * {@code orchestrator.yml}. Using the real binder keeps the tests honest about
 * the configuration model — including the snake_case spellings taken from the
 * reference configuration — instead of hand-building records.
 */
public final class TestProperties {

    private TestProperties() {
    }

    public static SigningProperties signing(Map<String, Object> values) {
        return binder(values).bindOrCreate("signing", SigningProperties.class);
    }

    public static CscProperties csc(Map<String, Object> values) {
        return binder(values).bindOrCreate("csc-config", CscProperties.class);
    }

    private static Binder binder(Map<String, Object> values) {
        return new Binder(new MapConfigurationPropertySource(new HashMap<>(values)));
    }
}
