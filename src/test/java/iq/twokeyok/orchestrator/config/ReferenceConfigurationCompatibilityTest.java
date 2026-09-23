package iq.twokeyok.orchestrator.config;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import iq.twokeyok.orchestrator.appearance.AppearanceLayout;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate;
import iq.twokeyok.orchestrator.config.SigningProperties.CredentialStrategy;
import iq.twokeyok.orchestrator.signing.PadesLevel;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Binds an excerpt of the <em>deployed</em> Ascertia Orchestrator configuration
 * and checks that the values this product implements arrive intact.
 *
 * <p>This is the test that backs the claim in the README: an operator can copy
 * their working {@code application.yml} across, and the ADSS endpoints, profile
 * ids, signature settings, appearances and registered clients bind without being
 * rewritten. Keys the reference file carries for features this product does not
 * implement — {@code one_time_signing}, the DSS revocation tuning, the XAdES and
 * CAdES settings — are simply ignored, which this test also pins down.</p>
 */
class ReferenceConfigurationCompatibilityTest {

    private static SigningProperties signing;
    private static CscProperties csc;

    @BeforeAll
    static void bindReferenceConfiguration() throws IOException {
        // Bound through an Environment, which is the same machinery Spring Boot
        // uses at start-up — including unwrapping the YAML loader's origin
        // tracking, which a raw map source does not do.
        Binder binder = Binder.get(environmentFor("reference-application.yml"));
        signing = binder.bindOrCreate("signing", SigningProperties.class);
        csc = binder.bindOrCreate("csc-config", CscProperties.class);
    }

    private static Environment environmentFor(String resource) throws IOException {
        List<PropertySource<?>> sources =
                new YamlPropertySourceLoader().load(resource, new ClassPathResource(resource));
        assertThat(sources).isNotEmpty();
        StandardEnvironment environment = new StandardEnvironment();
        sources.forEach(source -> environment.getPropertySources().addFirst(source));
        return environment;
    }

    @Test
    void bindsTheAdssGateway() {
        assertThat(signing.gateway().url()).isEqualTo("http://localhost:8777/adss/signing/hdsi");
        assertThat(signing.gateway().clientId()).isEqualTo("Orchestrator-Signing");
        assertThat(signing.gateway().pdfProfileId()).isEqualTo("adss:signing:profile:001");
    }

    @Test
    void bindsTheVerificationAndTimestampServices() {
        assertThat(signing.verification().url())
                .isEqualTo("http://adss-verify.internal.example/adss/verification/dss");
        assertThat(signing.verification().clientId()).isEqualTo("Orchestrator-Verify");
        assertThat(signing.verification().profileId()).isEqualTo("adss:verification:profile:001");
        assertThat(signing.verification().requestMode()).isEqualTo(2);

        assertThat(signing.dss().tsa().url()).isEqualTo("https://adss-tsa.internal.example:8778/adss/tsa");
        assertThat(signing.dss().tsa().policyId()).isEqualTo("2.16.368.1.2.1.6");
        assertThat(signing.dss().ocsp().url()).isEqualTo("http://adss-ocsp.internal.example/adss/ocsp");
    }

    @Test
    void bindsTheRemoteAuthorisationService() {
        assertThat(signing.ras().url()).isEqualTo("https://adss-ras.internal.example");
        assertThat(signing.ras().clientId()).isEqualTo("orchestrator");
        assertThat(signing.ras().profileId()).isEqualTo("adss:ras:profile:005");
        assertThat(signing.ras().deviceId()).isEqualTo("SIGNING_ORCHESTRATOR_DEVICE");
        assertThat(signing.ras().keystoreType()).isEqualTo("PKCS12");
        assertThat(signing.ras().hasClientCredentials()).isTrue();
    }

    @Test
    void bindsTheSignatureDefaults() {
        SigningProperties.Signature signature = signing.dss().signature();
        assertThat(signature.hashAlgorithm()).isEqualTo("SHA384");
        assertThat(signature.dictionarySize()).isEqualTo(12000);
        assertThat(signature.computeHash()).isTrue();
        assertThat(signature.signatureLevel()).isEqualTo("PAdES_BASELINE_LTA");
    }

    @Test
    void mapsTheConfiguredLevelOntoTheSdkPadesType() {
        assertThat(PadesLevel.toSdkType(signing.dss().signature().signatureLevel()))
                .isEqualTo(PadesLevel.PADES_B_LTA);
    }

    @Test
    void bindsTheTruststoreAndCredentialStrategy() {
        assertThat(signing.truststorePath())
                .isEqualTo("/appdata/ascertia/orchestrator/config/adss-truststore.jks");
        assertThat(signing.defaultCredentialStrategy()).isEqualTo(CredentialStrategy.LATEST);
        assertThat(signing.basicAuthType()).isEqualTo("implicit");
        assertThat(signing.debugMode()).isFalse();
    }

    @Test
    void bindsTheAppearanceCatalogue() {
        SigningProperties.Appearance appearance = signing.dss().signature().appearance();
        assertThat(appearance.enabled()).isTrue();
        assertThat(appearance.useDefault()).isTrue();
        assertThat(appearance.appearances()).hasSize(1);

        SigningProperties.AppearanceTemplateConfig template = appearance.appearances().get(0);
        assertThat(template.templateId()).isEqualTo("default_signature_appearance");
        assertThat(template.enabled()).isFalse();
        assertThat(template.signatureTextPosition()).isEqualTo("BOTTOM");
        assertThat(template.signedBy().value()).isEqualTo("Entity Name");
        assertThat(template.signedBy().label()).isEqualTo("Signed By: ");
        assertThat(template.signedBy().includeLabel()).isFalse();
        assertThat(template.signingDate().value()).isEqualTo("yyyy.MM.dd HH:mm:ss ZZ");
        assertThat(template.textFont().name()).isEqualTo("Helvetica");
        assertThat(template.textFont().size()).isEqualTo(6);
        assertThat(template.textFont().color().b()).isEqualTo(254);
        assertThat(template.textBackgroundColor().a()).isEqualTo(0.5);
        assertThat(template.signatureField().pageNo()).isEqualTo(1);
        assertThat(template.signatureField().x()).isEqualTo(10);
        assertThat(template.signatureField().y()).isEqualTo(650);
        assertThat(template.signatureField().width()).isEqualTo(200);
        assertThat(template.signatureField().height()).isEqualTo(80);
        assertThat(template.companyLogo().value()).isEqualTo("images/company-seal.png");
    }

    @Test
    void laysOutTheConfiguredAppearanceForTheAdssDocument() {
        SigningProperties.AppearanceTemplateConfig configured =
                signing.dss().signature().appearance().appearances().get(0);

        // No config directory, so the logo cannot be read; that is logged and the
        // rest of the template still lays out.
        AppearanceTemplate template = AppearanceLayout.toTemplate(configured, null);

        assertThat(template.templateId()).isEqualTo("default_signature_appearance");
        assertThat(template.isEnabled()).isFalse();
        assertThat(template.width()).isEqualTo(200);
        assertThat(template.height()).isEqualTo(80);
        assertThat(template.signatureField().pageNo()).isEqualTo(1);

        // The two configured lines are stacked, in reading order, with positions.
        assertThat(template.fields()).containsOnlyKeys(
                AppearanceTemplate.Fields.SIGNED_BY, AppearanceTemplate.Fields.SIGNING_DATE);
        AppearanceTemplate.Field signedBy = template.fields().get(AppearanceTemplate.Fields.SIGNED_BY);
        AppearanceTemplate.Field date = template.fields().get(AppearanceTemplate.Fields.SIGNING_DATE);
        assertThat(signedBy.value()).isEqualTo("Entity Name");
        assertThat(signedBy.position()).isNotNull();
        assertThat(date.position().y()).isGreaterThan(signedBy.position().y());
    }

    @Test
    void bindsTheRegisteredClients() {
        assertThat(csc.registeredClients())
                .extracting(CscProperties.RegisteredClient::clientId)
                .containsExactly("sh-client", "ica_eseal_stage");
        assertThat(csc.registeredClients().get(0).authorities())
                .containsExactly("ROLE_CLIENT_CREDENTIALS");
        assertThat(csc.registeredClients().get(0).enabled()).isTrue();
        assertThat(csc.cacheExpiry()).isEqualTo(60);
        assertThat(csc.cscV1Info().specs()).isEqualTo("1.0.4.0");
        assertThat(csc.cscV1Info().region()).isEqualTo("AE");
    }

    @Test
    void ignoresKeysForFeaturesThisProductDoesNotImplement() {
        // one_time_signing, the DSS revocation tuning and the XAdES/CAdES settings
        // are present in the reference file. Binding must not fail over them, and
        // they must not appear as behaviour: nothing reads them.
        assertThat(signing.signers()).isEmpty();
        assertThat(signing.limits().maxFilesPerRequest()).isEqualTo(20);
    }
}
