package iq.twokeyok.orchestrator.config;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;

import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The whole API surface — request bodies, appearance templates on disk and error
 * responses — uses {@code snake_case}, matching the TwoKeyOk MiddleWare guide
 * ({@code error_code}, {@code template_id}, {@code include_label}, …).
 */
@Configuration
public class JacksonConfig {

    @Bean
    Jackson2ObjectMapperBuilderCustomizer orchestratorJsonCustomizer() {
        return builder -> builder
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .failOnUnknownProperties(false);
    }
}
