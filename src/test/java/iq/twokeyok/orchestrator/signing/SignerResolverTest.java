package iq.twokeyok.orchestrator.signing;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.TestProperties;
import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.security.ClientRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignerResolverTest {

    private Map<String, Object> config;

    @BeforeEach
    void setUp() {
        config = new LinkedHashMap<>();
        config.put("signing.gateway.client_id", "Orchestrator-Signing");
        config.put("signing.gateway.pdf_profile_id", "adss:signing:profile:001");
        config.put("signing.dss.signature.hash_algorithm", "SHA384");
        config.put("signing.dss.signature.signature_level", "PAdES_BASELINE_LTA");
        config.put("signing.dss.signature.container_type", "NONE");
        config.put("signing.default_credential_strategy", "LATEST");

        config.put("csc-config.registered-clients[0].client-id", "hr_portal");
        config.put("csc-config.registered-clients[0].client-secret", "s3cret");
        config.put("csc-config.registered-clients[0].adss-client-id", "adss_hr");
        config.put("csc-config.registered-clients[0].default-signer-id", "ministry_eseal");
        config.put("csc-config.registered-clients[0].allowed-signer-ids[0]", "ministry_eseal");
        config.put("csc-config.registered-clients[0].overrides.allow-request-appearance", "false");

        config.put("csc-config.registered-clients[1].client-id", "case_mgmt");
        config.put("csc-config.registered-clients[1].client-secret", "other");
        config.put("csc-config.registered-clients[1].allowed-signer-ids[0]", "john_doe");

        config.put("signing.signers.ministry_eseal.type", "ESEAL");
        config.put("signing.signers.ministry_eseal.profile-id", "adss:signing:profile:005");
        config.put("signing.signers.ministry_eseal.certificate-alias", "ministry_cert");
        config.put("signing.signers.ministry_eseal.overrides.appearance-template", "eseal_signature_appearance");
        config.put("signing.signers.ministry_eseal.overrides.signed-by", "Ministry of Communications");

        config.put("signing.signers.john_doe.type", "NATURAL_PERSON");
        config.put("signing.signers.john_doe.credential-id", "johnDoe");
        config.put("signing.signers.john_doe.user-id", "john.doe");

        config.put("signing.signers.no_credential.type", "ESEAL");

        config.put("signing.signers.retired_signer.type", "ESEAL");
        config.put("signing.signers.retired_signer.enabled", "false");
        config.put("signing.signers.retired_signer.certificate-alias", "old_cert");
    }

    private SignerResolver resolver() {
        SigningProperties signing = TestProperties.signing(config);
        CscProperties csc = TestProperties.csc(config);
        return new SignerResolver(signing, new ClientRegistry(csc, signing));
    }

    @Test
    void appliesSignerOverridesOnTopOfTheSignatureDefaults() {
        EffectiveSignerConfig resolved = resolver().resolve(
                AuthenticatedCaller.client("hr_portal"), "ministry_eseal", null);

        assertThat(resolved.type()).isEqualTo(SignerType.ESEAL);
        assertThat(resolved.adssClientId()).isEqualTo("adss_hr");
        assertThat(resolved.profileId()).isEqualTo("adss:signing:profile:005");
        assertThat(resolved.certificateAlias()).isEqualTo("ministry_cert");
        assertThat(resolved.hashAlgorithm()).isEqualTo("SHA384");
        assertThat(resolved.appearanceTemplate()).isEqualTo("eseal_signature_appearance");
        assertThat(resolved.textDefaults().signedBy()).isEqualTo("Ministry of Communications");
        assertThat(resolved.userId()).isNull();
        assertThat(resolved.isNaturalPerson()).isFalse();
    }

    @Test
    void mapsTheEtsiSignatureLevelOntoTheSdkPadesType() {
        assertThat(resolver().resolve(AuthenticatedCaller.client("hr_portal"), "ministry_eseal", null)
                .padesSignatureType()).isEqualTo(PadesLevel.PADES_B_LTA);

        // B and T are produced by the ADSS signing profile, so nothing is requested.
        config.put("signing.dss.signature.signature_level", "PAdES_BASELINE_B");
        assertThat(resolver().resolve(AuthenticatedCaller.client("hr_portal"), "ministry_eseal", null)
                .padesSignatureType()).isNull();

        config.put("signing.dss.signature.signature_level", "PAdES_BASELINE_LT");
        assertThat(resolver().resolve(AuthenticatedCaller.client("hr_portal"), "ministry_eseal", null)
                .padesSignatureType()).isEqualTo(PadesLevel.PADES_LT);
    }

    @Test
    void fallsBackToTheGatewayProfileWhenTheSignerHasNone() {
        EffectiveSignerConfig resolved = resolver().resolve(
                AuthenticatedCaller.client("case_mgmt"), "john_doe", null);

        assertThat(resolved.profileId()).isEqualTo("adss:signing:profile:001");
        assertThat(resolved.isNaturalPerson()).isTrue();
        assertThat(resolved.userId()).isEqualTo("john.doe");
        assertThat(resolved.certificateAlias()).isEqualTo("johnDoe");
    }

    @Test
    void clientOverrideAppliesWhenTheSignerIsSilent() {
        EffectiveSignerConfig resolved = resolver().resolve(
                AuthenticatedCaller.client("hr_portal"), "ministry_eseal", null);

        assertThat(resolved.allowRequestAppearance()).isFalse();
        assertThat(resolved.allowRequestAppearanceTemplate()).isTrue();
    }

    @Test
    void fallsBackToTheClientDefaultSigner() {
        assertThat(resolver().resolve(AuthenticatedCaller.client("hr_portal"), null, null).signerId())
                .isEqualTo("ministry_eseal");
    }

    @Test
    void requiresSignerIdWhenTheClientHasNoDefault() {
        assertThatThrownBy(() -> resolver().resolve(AuthenticatedCaller.client("case_mgmt"), null, null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.SIGNER_ID_MISSING);
    }

    @Test
    void refusesASignerTheClientIsNotAllowedToUse() {
        assertThatThrownBy(() -> resolver().resolve(AuthenticatedCaller.client("hr_portal"), "john_doe", null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.SIGNER_NOT_ALLOWED);
    }

    @Test
    void refusesAnUnknownOrDisabledSigner() {
        assertThatThrownBy(() -> resolver().resolve(AuthenticatedCaller.client("case_mgmt"), "nobody", null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.UNKNOWN_SIGNER);

        assertThatThrownBy(() -> resolver().resolve(AuthenticatedCaller.client("case_mgmt"), "retired_signer", null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.SIGNER_DISABLED);
    }

    @Test
    void aTokenHolderCannotSignAsSomebodyElse() {
        AuthenticatedCaller signer = AuthenticatedCaller.signer("case_mgmt", "john_doe", null);

        assertThatThrownBy(() -> resolver().resolve(signer, "ministry_eseal", null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.SIGNER_NOT_ALLOWED);

        assertThat(resolver().resolve(signer, null, null).signerId()).isEqualTo("john_doe");
    }

    @Test
    void refusesACredentialThatContradictsTheConfiguredOne() {
        assertThatThrownBy(() ->
                resolver().resolve(AuthenticatedCaller.client("case_mgmt"), "john_doe", "someoneElse"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.NO_SIGNER_CERTIFICATE);
    }

    @Test
    void credentialStrategyLatestLeavesTheChoiceToTheAdssProfile() {
        config.put("csc-config.registered-clients[1].allowed-signer-ids[1]", "no_credential");

        EffectiveSignerConfig resolved = resolver().resolve(
                AuthenticatedCaller.client("case_mgmt"), "no_credential", null);

        assertThat(resolved.certificateAlias()).isNull();
    }

    @Test
    void credentialStrategyNoneRequiresAnExplicitCredential() {
        config.put("signing.default_credential_strategy", "NONE");
        config.put("csc-config.registered-clients[1].allowed-signer-ids[1]", "no_credential");

        assertThatThrownBy(() -> resolver().resolve(
                AuthenticatedCaller.client("case_mgmt"), "no_credential", null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.CREDENTIAL_REQUIRED);
    }
}
