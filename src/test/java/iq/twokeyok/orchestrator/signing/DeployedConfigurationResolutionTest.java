package iq.twokeyok.orchestrator.signing;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.security.ClientRegistry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Resolves a signer from a YAML file shaped like the staging deployment.
 *
 * <p>Written to chase a live failure: the deployed configuration set
 * {@code local_hash: false}, the preflight printed {@code false}, and the signing
 * backend logged {@code local_hash=true} — which sends the SDK down its
 * client-side hashing path, where it needs the named signature field to already
 * exist in the document and throws
 * {@code The signature field 'Signature1' does not exist} before any request is
 * sent. The flags are resolved through {@code defaults → client → signer}, so
 * they are asserted here on the resolved config rather than on the raw
 * properties.</p>
 */
class DeployedConfigurationResolutionTest {

    @Test
    void resolvesTheSignatureFlagsAsTheFileStatesThem() throws IOException {
        EffectiveSignerConfig resolved = resolve();

        assertThat(resolved.localHash()).isFalse();
        assertThat(resolved.computeHash()).isTrue();
        assertThat(resolved.hashAlgorithm()).isEqualTo("SHA384");
        assertThat(resolved.signatureDictionarySize()).isEqualTo(12000);
        assertThat(resolved.signatureFieldName()).isEqualTo("Signature1");
        assertThat(resolved.padesSignatureType()).isEqualTo(PadesLevel.PADES_B_LTA);
    }

    @Test
    void resolvesTheIdentityAsTheFileStatesIt() throws IOException {
        EffectiveSignerConfig resolved = resolve();

        assertThat(resolved.signerId()).isEqualTo("techsource_eseal");
        assertThat(resolved.type()).isEqualTo(SigningProperties.SignerType.ESEAL);
        assertThat(resolved.profileId()).isEqualTo("adss:signing:profile:001");
        assertThat(resolved.adssClientId()).isEqualTo("Orchestrator-Signing");
        // Credential strategy LATEST: the ADSS profile picks the certificate.
        assertThat(resolved.certificateAlias()).isNull();
        assertThat(resolved.userId()).isNull();
    }

    private EffectiveSignerConfig resolve() throws IOException {
        Binder binder = Binder.get(environmentFor("deployed-eseal.yml"));
        SigningProperties signing = binder.bindOrCreate("signing", SigningProperties.class);
        CscProperties csc = binder.bindOrCreate("csc-config", CscProperties.class);

        SignerResolver resolver = new SignerResolver(signing, new ClientRegistry(csc, signing));
        return resolver.resolve(AuthenticatedCaller.client("hr_portal"), "techsource_eseal", null);
    }

    private static Environment environmentFor(String resource) throws IOException {
        List<PropertySource<?>> sources =
                new YamlPropertySourceLoader().load(resource, new ClassPathResource(resource));
        assertThat(sources).isNotEmpty();
        StandardEnvironment environment = new StandardEnvironment();
        sources.forEach(source -> environment.getPropertySources().addFirst(source));
        return environment;
    }
}
