package iq.twokeyok.orchestrator.appearance;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.TestProperties;
import iq.twokeyok.orchestrator.appearance.AppearanceService.TextDefaults;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.web.dto.SignatureAppearanceRequest;
import iq.twokeyok.orchestrator.web.dto.SignatureAppearanceRequest.TextField;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Exercises the appearance merge against the templates bundled in the jar, which
 * is what a fresh installation serves before anyone customises anything.
 */
class AppearanceServiceTest {

    private AppearanceService service;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper()
                .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        // A store path that does not exist makes the repository fall back to the
        // templates packaged under classpath:appearances/.
        AppearanceRepository repository = new AppearanceRepository(
                TestProperties.signing(Map.of(
                        "signing.dss.signature.appearance.store-path", "target/no-such-directory")),
                mapper);
        service = new AppearanceService(repository, new AppearanceXmlWriter());
    }

    @Test
    void listsTheBundledTemplates() {
        assertThat(service.list())
                .extracting(AppearanceTemplate::templateId)
                .contains("default_signature_appearance", "eseal_signature_appearance");
    }

    @Test
    void requestValueWinsOverConfiguredDefault() {
        SignatureAppearanceRequest request = new SignatureAppearanceRequest(
                null, new TextField("Signed By: ", true, "Ahmed Kareem"),
                null, null, null, null, null, null, null, null, null, null);

        ResolvedAppearance resolved = service.resolve("default_signature_appearance", request,
                new TextDefaults("Configured Name", null, "Configured reason", null, null),
                true, true);

        assertThat(resolved.signedBy()).isEqualTo("Ahmed Kareem");
        // Untouched values still come from the configuration.
        assertThat(resolved.reason()).isEqualTo("Configured reason");
        assertThat(new String(resolved.appearanceXml(), StandardCharsets.UTF_8))
                .contains("<Value>Ahmed Kareem</Value>");
    }

    @Test
    void usesConfiguredDefaultsWhenTheRequestMayNotOverride() {
        ResolvedAppearance resolved = service.resolve("eseal_signature_appearance", null,
                new TextDefaults("Ministry of Communications", null, "Officially sealed", "Baghdad", null),
                false, false);

        assertThat(resolved.signedBy()).isEqualTo("Ministry of Communications");
        assertThat(resolved.location()).isEqualTo("Baghdad");
    }

    @Test
    void rejectsRequestOverridesWhenTheClientMayNotChangeTheAppearance() {
        SignatureAppearanceRequest request = new SignatureAppearanceRequest(
                null, new TextField(null, null, "Someone Else"),
                null, null, null, null, null, null, null, null, null, null);

        assertThatThrownBy(() -> service.resolve("eseal_signature_appearance", request,
                TextDefaults.EMPTY, false, false))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.APPEARANCE_NOT_ALLOWED);
    }

    @Test
    void rejectsAnotherTemplateWhenTheClientIsPinnedToOne() {
        SignatureAppearanceRequest request = new SignatureAppearanceRequest(
                "default_signature_appearance", null, null, null, null, null, null, null, null, null, null, null);

        assertThatThrownBy(() -> service.resolve("eseal_signature_appearance", request,
                TextDefaults.EMPTY, true, false))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.APPEARANCE_NOT_ALLOWED);
    }

    @Test
    void reportsAnUnknownTemplate() {
        assertThatThrownBy(() -> service.resolve("does_not_exist", null, TextDefaults.EMPTY, true, true))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.APPEARANCE_NOT_FOUND);
    }

    @Test
    void rejectsMalformedBase64Images() {
        SignatureAppearanceRequest request = new SignatureAppearanceRequest(
                null, null, null, null, null, null, null, null, null, null,
                new SignatureAppearanceRequest.Image("!!!not-base64!!!", null), null);

        assertThatThrownBy(() -> service.resolve("eseal_signature_appearance", request,
                TextDefaults.EMPTY, true, true))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.INVALID_APPEARANCE);
    }

    @Test
    void takesTheSignatureBoxFromTheRequestWhenItIsComplete() {
        SignatureAppearanceRequest request = new SignatureAppearanceRequest(
                null, null, null, null, null, null, null, null, null,
                new SignatureAppearanceRequest.Box(100, 200, 180, 60, 3), null, null);

        ResolvedAppearance resolved = service.resolve("default_signature_appearance", request,
                TextDefaults.EMPTY, true, true);

        assertThat(resolved.box()).isNotNull();
        assertThat(resolved.box().x()).isEqualTo(100);
        assertThat(resolved.box().x2()).isEqualTo(280);
        assertThat(resolved.box().y2()).isEqualTo(260);
        assertThat(resolved.box().pageNo()).isEqualTo(3);
    }
}
