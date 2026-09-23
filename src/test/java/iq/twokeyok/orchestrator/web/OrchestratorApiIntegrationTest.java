package iq.twokeyok.orchestrator.web;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.signing.SignJob;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult.SignedDocument;
import iq.twokeyok.orchestrator.signing.SigningBackend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Drives the two endpoints through the full web stack — authentication filter,
 * controller, orchestration service, appearance merge and error mapping — with
 * the ADSS backend replaced by a recording stub, so no signing platform is
 * needed to prove the wiring.
 */
@SpringBootTest(properties = {
        // Point the optional config import at nothing, so the test is not affected
        // by the deployment configuration sitting in ./config.
        "ORCHESTRATOR_CONFIG_DIR=target/no-such-config-dir",
        // Bundled templates only, so the test does not depend on a config directory.
        "signing.dss.signature.appearance.store-path=target/no-such-appearance-dir",
        "signing.gateway.client_id=Orchestrator-Signing",
        "signing.gateway.pdf_profile_id=adss:signing:profile:001",
        "signing.dss.signature.hash_algorithm=SHA384",
        "signing.dss.signature.signature_level=PAdES_BASELINE_B",

        "csc-config.registered-clients[0].client-id=hr_portal",
        "csc-config.registered-clients[0].client-secret=s3cret",
        "csc-config.registered-clients[0].adss-client-id=samples_test_client",
        "csc-config.registered-clients[0].default-signer-id=ministry_eseal",
        "csc-config.registered-clients[0].allowed-signer-ids[0]=ministry_eseal",
        "csc-config.registered-clients[0].overrides.allow-request-appearance=false",
        "csc-config.registered-clients[0].overrides.allow-request-container-type=false",

        "csc-config.registered-clients[1].client-id=case_mgmt",
        "csc-config.registered-clients[1].client-secret=other",
        "csc-config.registered-clients[1].allowed-signer-ids[0]=john_doe",
        "csc-config.registered-clients[1].allowed-signer-ids[1]=ministry_eseal",

        "signing.signers.ministry_eseal.type=ESEAL",
        "signing.signers.ministry_eseal.profile-id=adss:signing:profile:005",
        "signing.signers.ministry_eseal.certificate-alias=ministry_cert",
        "signing.signers.ministry_eseal.require-pin=false",
        "signing.signers.ministry_eseal.overrides.appearance-template=eseal_signature_appearance",
        "signing.signers.ministry_eseal.overrides.signed-by=Ministry of Communications",

        "signing.signers.john_doe.type=NATURAL_PERSON",
        "signing.signers.john_doe.profile-id=adss:signing:profile:010",
        "signing.signers.john_doe.credential-id=johnDoe",
        "signing.signers.john_doe.user-id=john.doe",
        "signing.signers.john_doe.require-pin=true"
})
@AutoConfigureMockMvc
class OrchestratorApiIntegrationTest {

    private static final byte[] PDF = "%PDF-1.7\n%stub\n".getBytes(StandardCharsets.UTF_8);

    private static final String HR_PORTAL = basic("hr_portal", "s3cret");
    private static final String CASE_MGMT = basic("case_mgmt", "other");

    @Autowired
    private MockMvc mvc;

    @Autowired
    private RecordingSigningBackend backend;

    @BeforeEach
    void setUp() {
        backend.jobs.clear();
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static MockMultipartFile pdf(String name) {
        return new MockMultipartFile("input_files", name, MediaType.APPLICATION_PDF_VALUE, PDF);
    }

    // ---------------------------------------------------------- appearances --

    @Test
    void listsAppearancesForAnAuthenticatedClient() throws Exception {
        mvc.perform(get("/service/signing/appearances/list").header("Authorization", HR_PORTAL))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$[*].template_id")
                        .value(org.hamcrest.Matchers.hasItems(
                                "default_signature_appearance", "eseal_signature_appearance")))
                // Image payloads are replaced by a marker.
                .andExpect(jsonPath("$[?(@.template_id=='eseal_signature_appearance')]"
                        + ".fields.company_logo.has_image").exists());
    }

    @Test
    void refusesAnUnauthenticatedCall() throws Exception {
        mvc.perform(get("/service/signing/appearances/list"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_code").value(1117))
                .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    void refusesAWrongSecret() throws Exception {
        mvc.perform(get("/service/signing/appearances/list")
                        .header("Authorization", basic("hr_portal", "wrong")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_code").value(1009));
    }

    @Test
    void refusesAnUnknownClient() throws Exception {
        mvc.perform(get("/service/signing/appearances/list")
                        .header("Authorization", basic("nobody", "x")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_code").value(1005));
    }

    // --------------------------------------------------------------- signing --

    @Test
    void signsAnEsealAndReturnsThePdf() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("invoice.pdf")));

        SignJob job = backend.jobs.get(0);
        assertThat(job.config().type()).isEqualTo(SignerType.ESEAL);
        assertThat(job.config().adssClientId()).isEqualTo("samples_test_client");
        assertThat(job.config().profileId()).isEqualTo("adss:signing:profile:005");
        assertThat(job.config().certificateAlias()).isEqualTo("ministry_cert");
        assertThat(job.config().userId()).isNull();
        // The signer override selected the seal template and fixed the name.
        assertThat(job.appearance().templateId()).isEqualTo("eseal_signature_appearance");
        assertThat(job.appearance().signedBy()).isEqualTo("Ministry of Communications");
        assertThat(new String(job.appearance().appearanceXml(), StandardCharsets.UTF_8))
                .contains("<Value>Ministry of Communications</Value>");
    }

    @Test
    void usesTheClientDefaultSignerWhenSignerIdIsOmitted() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isOk());

        assertThat(backend.jobs.get(0).config().signerId()).isEqualTo("ministry_eseal");
    }

    @Test
    void requiresSignerIdWhenTheClientHasNoDefault() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1002));
    }

    @Test
    void zipsSeveralDocuments() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("a.pdf"))
                        .file(pdf("b.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/zip"));

        assertThat(backend.jobs.get(0).documents()).hasSize(2);
    }

    @Test
    void rejectsAnInputThatIsNotAPdf() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(new MockMultipartFile("input_files", "notes.txt", "text/plain",
                                "hello".getBytes(StandardCharsets.UTF_8)))
                        .param("signer_id", "ministry_eseal")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1101));

        assertThat(backend.jobs).isEmpty();
    }

    @Test
    void rejectsANaturalPersonRequestWithoutAPin() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("contract.pdf"))
                        .param("signer_id", "john_doe")
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1105));
    }

    @Test
    void passesTheNaturalPersonPinAndRasUserToTheBackend() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("contract.pdf"))
                        .param("signer_id", "john_doe")
                        .param("pin", "12345678")
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isOk());

        SignJob job = backend.jobs.get(0);
        assertThat(job.config().type()).isEqualTo(SignerType.NATURAL_PERSON);
        assertThat(job.config().userId()).isEqualTo("john.doe");
        assertThat(job.config().certificateAlias()).isEqualTo("johnDoe");
        assertThat(job.config().credentialPassword()).isEqualTo("12345678");
    }

    @Test
    void refusesASignerTheClientMayNotUse() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "john_doe")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error_code").value(1104));
    }

    @Test
    void refusesAnAppearanceOverrideFromAClientThatMayNotSendOne() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .param("signature_appearance",
                                "{\"reason\":{\"value\":\"Something else entirely\"}}")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error_code").value(1107));
    }

    @Test
    void appliesAnAppearanceOverrideFromAClientThatMay() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("contract.pdf"))
                        .param("signer_id", "john_doe")
                        .param("pin", "12345678")
                        .param("signature_appearance", """
                                {"template_id":"default_signature_appearance",
                                 "signed_by":{"label":"Signed By: ","include_label":true,"value":"John Doe"},
                                 "reason":{"value":"I approve this contract"},
                                 "signature_field":{"x":100,"y":200,"width":180,"height":60,"page_no":2}}""")
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isOk());

        SignJob job = backend.jobs.get(0);
        assertThat(job.appearance().signedBy()).isEqualTo("John Doe");
        assertThat(job.appearance().reason()).isEqualTo("I approve this contract");
        assertThat(job.appearance().box().pageNo()).isEqualTo(2);
        assertThat(job.appearance().box().x2()).isEqualTo(280);
    }

    @Test
    void reportsMalformedAppearanceJson() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("contract.pdf"))
                        .param("signer_id", "john_doe")
                        .param("pin", "1234")
                        .param("signature_appearance", "{not json")
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1108));
    }

    @Test
    void rejectsPreComputedHashes() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("contract.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .param("hashes", "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1118));
    }

    /**
     * A client pinned to one container may still restate it. The API guide's own
     * curl example sends {@code container_type=NONE}, so refusing a request that
     * changes nothing would reject callers following the documentation.
     */
    @Test
    void allowsAPinnedClientToRestateTheContainerItAlreadyHas() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .param("container_type", "NONE")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));

        assertThat(backend.jobs).hasSize(1);
    }

    @Test
    void refusesAPinnedClientThatActuallyChangesTheContainer() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .param("container_type", "ASiC-E")
                        .header("Authorization", HR_PORTAL))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error_code").value(1110));

        assertThat(backend.jobs).isEmpty();
    }

    @Test
    void rejectsAnUnsupportedContainerType() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .param("container_type", "ASiC-S/T")
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1109));
    }

    @Test
    void producesAnAsicContainerWhenAsked() throws Exception {
        mvc.perform(multipart("/service/sign")
                        .file(pdf("invoice.pdf"))
                        .param("signer_id", "ministry_eseal")
                        .param("container_type", "ASiC-E")
                        .header("Authorization", CASE_MGMT))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/vnd.etsi.asic-e+zip"));
    }

    @Test
    void rejectsABearerTokenWhileBearerAuthenticationIsDisabled() throws Exception {
        mvc.perform(get("/service/signing/appearances/list")
                        .header("Authorization", "Bearer not.a.token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_code").value(1013));
    }

    // ------------------------------------------------------------------ stub --

    @TestConfiguration
    static class StubBackendConfiguration {

        @Bean
        @Primary
        RecordingSigningBackend recordingSigningBackend() {
            return new RecordingSigningBackend();
        }
    }

    /** Records the jobs it is handed and returns each input document unchanged. */
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
