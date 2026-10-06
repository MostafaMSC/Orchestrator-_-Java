package iq.twokeyok.orchestrator.web;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import iq.twokeyok.orchestrator.appearance.AppearanceRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The appearance management endpoints of the API guide: list, get, create,
 * update and delete.
 *
 * <p>The store is a directory of JSON files, one per {@code template_id}, so
 * these tests assert on the filesystem as well as on the responses — an operator
 * has to be able to see, back up and hand-edit what callers create.</p>
 */
@SpringBootTest(properties = {
        "ORCHESTRATOR_CONFIG_DIR=target/no-such-config-dir",
        "signing.basic-auth-type=client_credentials",
        "signing.dss.signature.appearance.store-path=target/test-appearance-store",
        "signing.dss.signature.appearance.reload-always=true",
        // One template from configuration, to prove the API will not overwrite it.
        "signing.dss.signature.appearance.appearances[0].template_id=from_config",
        "signing.dss.signature.appearance.appearances[0].enabled=true",
        "csc-config.registered-clients[0].client-id=hr_portal",
        "csc-config.registered-clients[0].client-secret=s3cret",
})
@AutoConfigureMockMvc
class AppearanceCrudTest {

    private static final String AUTH = "Basic aHJfcG9ydGFsOnMzY3JldA==";  // hr_portal:s3cret
    private static final Path STORE = Path.of("target/test-appearance-store");

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AppearanceRepository repository;

    @BeforeEach
    void clearStore() throws Exception {
        if (Files.isDirectory(STORE)) {
            try (var files = Files.list(STORE)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
        }
        repository.reload();
    }

    private static String template(String id, String label) {
        return """
                {
                  "template_id": "%s",
                  "name": "Test appearance",
                  "enabled": true,
                  "width": 400,
                  "height": 120,
                  "signature_field": { "x": 200, "y": 200, "width": 100, "height": 100, "page_no": 1 },
                  "fields": {
                    "signed_by": { "include": true, "label": "%s", "show_label": true }
                  }
                }
                """.formatted(id, label);
    }

    @Test
    void createsATemplateAndReturns201() throws Exception {
        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(template("my_seal", "Sealed By")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.template_id").value("my_seal"));

        assertThat(STORE.resolve("my_seal.json")).exists();
        assertThat(repository.findById("my_seal")).isPresent();
    }

    @Test
    void updatingAnExistingTemplateReturns200() throws Exception {
        mvc.perform(post("/service/signing/appearances").header("Authorization", AUTH)
                .contentType(MediaType.APPLICATION_JSON).content(template("my_seal", "Sealed By")));

        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(template("my_seal", "Approved By")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fields.signed_by.label").value("Approved By"));
    }

    @Test
    void getsATemplateById() throws Exception {
        mvc.perform(post("/service/signing/appearances").header("Authorization", AUTH)
                .contentType(MediaType.APPLICATION_JSON).content(template("my_seal", "Sealed By")));

        mvc.perform(get("/service/signing/appearances/my_seal").header("Authorization", AUTH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.template_id").value("my_seal"))
                .andExpect(jsonPath("$.signature_field.x").value(200));
    }

    @Test
    void listsCreatedTemplatesAlongsideConfiguredOnes() throws Exception {
        mvc.perform(post("/service/signing/appearances").header("Authorization", AUTH)
                .contentType(MediaType.APPLICATION_JSON).content(template("my_seal", "Sealed By")));

        mvc.perform(get("/service/signing/appearances/list").header("Authorization", AUTH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.template_id == 'my_seal')]").isNotEmpty())
                .andExpect(jsonPath("$[?(@.template_id == 'from_config')]").isNotEmpty());
    }

    @Test
    void deletesATemplate() throws Exception {
        mvc.perform(post("/service/signing/appearances").header("Authorization", AUTH)
                .contentType(MediaType.APPLICATION_JSON).content(template("my_seal", "Sealed By")));

        mvc.perform(delete("/service/signing/appearances/my_seal").header("Authorization", AUTH))
                .andExpect(status().isNoContent());

        assertThat(STORE.resolve("my_seal.json")).doesNotExist();
        mvc.perform(get("/service/signing/appearances/my_seal").header("Authorization", AUTH))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1106));
    }

    @Test
    void refusesToChangeATemplateDeclaredInTheConfiguration() throws Exception {
        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(template("from_config", "Hijacked")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error_code").value(1125));
    }

    @Test
    void refusesToDeleteATemplateDeclaredInTheConfiguration() throws Exception {
        mvc.perform(delete("/service/signing/appearances/from_config").header("Authorization", AUTH))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error_code").value(1125));
    }

    @Test
    void rejectsATemplateWithoutAnId() throws Exception {
        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"no id\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1123));
    }

    @Test
    void rejectsATemplateIdThatWouldEscapeTheStore() throws Exception {
        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(template("../../etc/passwd", "Nope")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_code").value(1123));

        assertThat(repository.findById("../../etc/passwd")).isEmpty();
    }

    @Test
    void acceptsCompanyLogoAtTheTopLevelAsTheApiGuideDescribesIt() throws Exception {
        // A 1x1 PNG is enough: nothing here decodes it, the template only stores it.
        String png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGMAAQAABQAB";

        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "template_id": "top_level_logo",
                                  "company_logo": "%s",
                                  "hand_signature": "%s"
                                }
                                """.formatted(png, png)))
                .andExpect(status().isCreated())
                // Folded into fields, where everything downstream reads images.
                .andExpect(jsonPath("$.fields.company_logo.value").value(png))
                .andExpect(jsonPath("$.fields.company_logo.image_name").value("company-logo.png"))
                .andExpect(jsonPath("$.fields.hand_signature.value").value(png))
                // Not echoed at the top level as well: one copy of the payload.
                .andExpect(jsonPath("$.company_logo").doesNotExist());
    }

    @Test
    void aNestedImageValueWinsOverTheTopLevelOne() throws Exception {
        mvc.perform(post("/service/signing/appearances")
                        .header("Authorization", AUTH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "template_id": "both_spellings",
                                  "company_logo": "dG9wLWxldmVs",
                                  "fields": {
                                    "company_logo": { "include": true, "value": "bmVzdGVk",
                                                      "image_name": "mine.png" }
                                  }
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fields.company_logo.value").value("bmVzdGVk"))
                .andExpect(jsonPath("$.fields.company_logo.image_name").value("mine.png"));
    }

    @Test
    void listsAtTheCollectionRootAsWellAsAtList() throws Exception {
        mvc.perform(get("/service/signing/appearances").header("Authorization", AUTH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.template_id == 'from_config')]").isNotEmpty());
    }

    @Test
    void reportsAWrongMethodAsSuchRatherThanAsAnInternalError() throws Exception {
        mvc.perform(delete("/service/signing/appearances").header("Authorization", AUTH))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error_code").value(405));
    }

    @Test
    void requiresAuthentication() throws Exception {
        mvc.perform(get("/service/signing/appearances/list")).andExpect(status().isUnauthorized());
        mvc.perform(delete("/service/signing/appearances/my_seal")).andExpect(status().isUnauthorized());
    }
}
