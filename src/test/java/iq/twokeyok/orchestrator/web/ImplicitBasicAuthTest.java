package iq.twokeyok.orchestrator.web;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.mock.web.MockPart;
import org.springframework.test.web.servlet.MockMvc;

import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.signing.SignJob;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult.SignedDocument;
import iq.twokeyok.orchestrator.signing.SigningBackend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code signing.basic_auth_type: implicit} — the scheme the deployed Ascertia
 * Orchestrator uses, where {@code Basic base64(signerId:password)} carries the
 * signer identity and their credential password, and the request body needs
 * neither {@code signer_id} nor {@code pin}.
 *
 * <p>The request these tests send is the one a caller written against that API
 * already sends:</p>
 *
 * <pre>
 * curl -X POST .../orchestrator/service/sign \
 *   -H 'Authorization: Basic base64(signer@example.com:password)' \
 *   -F 'input_files=@document.pdf' \
 *   -F 'signature_appearance={"template_id":"..."};type=application/json'
 * </pre>
 */
@SpringBootTest(properties = {
        "ORCHESTRATOR_CONFIG_DIR=target/no-such-config-dir",
        "signing.dss.signature.appearance.store-path=target/no-such-appearance-dir",
        "signing.basic-auth-type=implicit",
        "signing.gateway.client_id=mustafa_lab_platfrom",
        "signing.gateway.pdf_profile_id=adss:signing:profile:009",
        "signing.dss.signature.signature_level=PAdES_BASELINE_B",
        // Identity arrives with the request, so no signer is pre-registered.
        "signing.dynamic-signer.enabled=true",
        "signing.dynamic-signer.type=NATURAL_PERSON",
})
@AutoConfigureMockMvc
class ImplicitBasicAuthTest {

    private static final String SIGNER = "signer@example.com";
    private static final String PASSWORD = "not-a-real-password";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private RecordingSigningBackend backend;

    @BeforeEach
    void setUp() {
        backend.jobs.clear();
    }

    @Test
    void takesTheSignerAndThePasswordFromTheAuthorizationHeader() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf())
                        .header("Authorization", basic(SIGNER, PASSWORD)))
                .andExpect(status().isOk());

        assertThat(backend.jobs).hasSize(1);
        SignJob job = backend.jobs.get(0);
        assertThat(job.config().signerId()).isEqualTo(SIGNER);
        assertThat(job.config().userId()).isEqualTo(SIGNER);
        assertThat(job.config().type()).isEqualTo(SignerType.NATURAL_PERSON);
        // The header's password is what ADSS receives as the credential password.
        assertThat(job.config().credentialPassword()).isEqualTo(PASSWORD);
        assertThat(job.config().profileId()).isEqualTo("adss:signing:profile:009");
    }

    @Test
    void acceptsAnAppearanceTemplateAlongsideImplicitCredentials() throws Exception {
        // curl --form 'signature_appearance="{...}";type=application/json' sends a
        // part with a content type and no filename, which is how the Ascertia
        // Orchestrator API is called. A MockPart reproduces that; a
        // MockMultipartFile would make it a file upload instead.
        MockPart appearance = new MockPart("signature_appearance",
                "{\"template_id\":\"default_signature_appearance\"}".getBytes(StandardCharsets.UTF_8));
        appearance.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        mvc.perform(multipart("/service/sign")
                        .file(pdf())
                        .part(appearance)
                        .header("Authorization", basic(SIGNER, PASSWORD)))
                .andExpect(status().isOk());

        assertThat(backend.jobs).hasSize(1);
        assertThat(backend.jobs.get(0).appearance()).isNotNull();
    }

    @Test
    void aRequestPinStillWinsOverTheHeaderPassword() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf())
                        .param("pin", "pin-from-the-form")
                        .header("Authorization", basic(SIGNER, PASSWORD)))
                .andExpect(status().isOk());

        assertThat(backend.jobs.get(0).config().credentialPassword()).isEqualTo("pin-from-the-form");
    }

    @Test
    void rejectsAnEmptyPassword() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf())
                        .header("Authorization", basic(SIGNER, "")))
                .andExpect(status().isUnauthorized());

        assertThat(backend.jobs).isEmpty();
    }

    @Test
    void stillRequiresAnAuthorizationHeader() throws Exception {
        mvc.perform(multipart("/service/sign").file(pdf()))
                .andExpect(status().isUnauthorized());

        assertThat(backend.jobs).isEmpty();
    }

    @Test
    void refusesToActForADifferentSignerThanTheOneAuthenticated() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf())
                        .param("signer_id", "someone.else@example.com")
                        .header("Authorization", basic(SIGNER, PASSWORD)))
                .andExpect(status().isForbidden());

        assertThat(backend.jobs).isEmpty();
    }

    private static MockMultipartFile pdf() {
        return new MockMultipartFile("input_files", "document.pdf", "application/pdf",
                "%PDF-1.4 test".getBytes(StandardCharsets.UTF_8));
    }

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    @TestConfiguration
    static class StubBackend {

        @Bean
        @Primary
        RecordingSigningBackend recordingSigningBackend() {
            return new RecordingSigningBackend();
        }
    }

    static class RecordingSigningBackend implements SigningBackend {
        final List<SignJob> jobs = new ArrayList<>();

        @Override
        public SignResult signPades(SignJob job) {
            jobs.add(job);
            List<SignedDocument> signed = job.documents().stream()
                    .map(document -> new SignedDocument(document.fileName(), document.content()))
                    .toList();
            return new SignResult(signed, "txn-test-1");
        }
    }
}
