package iq.twokeyok.orchestrator.appearance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Ascertia Orchestrator's {@code appearancetemplate.signatureappearance}
 * JSON, read and written. The sample mirrors the key sets found in a deployed
 * table, vendor-specific keys included.
 */
class AscertiaAppearanceCodecTest {

    /** A short but valid Base64 value: images from a row are data, never paths. */
    private static final String LOGO = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    private static final String ASCERTIA_ROW = """
            {"template_id":"Test_Nbi","enabled":true,
             "signature_text_position":"RIGHT",
             "signed_by":{"label":"Signed By: ","value":"Ministry","enabled":true,"include_label":true,"signer-dn-value":false},
             "signing_date":{"label":"Date: ","value":"yyyy.MM.dd HH:mm:ss ZZ","enabled":true,"include_label":true,"apostrophe-date-offset":true},
             "reason":{"label":"Reason: ","value":"Approved","enabled":true,"include_label":true},
             "location":{"label":"Location: ","value":"Baghdad","enabled":false,"include_label":true},
             "user_info":{"enabled":true,"include_label":false},
             "text_font":{"name":"Helvetica","size":7,"color":{"r":0,"g":0,"b":0,"a":1.0},"embed":false},
             "background_color":{"r":255,"g":255,"b":255,"a":0.5},
             "signature_field":{"x":150,"y":170,"width":345,"height":90,"page_no":1,"field_id":""},
             "company_logo":{"enabled":true,"value":"%s"}}
            """.formatted(LOGO);

    private final ObjectMapper mapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    private final AscertiaAppearanceCodec codec = new AscertiaAppearanceCodec(mapper);

    @Test
    void readsARowOfTheAscertiaTable() throws Exception {
        AppearanceTemplate template = codec.fromJson(ASCERTIA_ROW);

        assertThat(template.templateId()).isEqualTo("Test_Nbi");
        assertThat(template.isEnabled()).isTrue();
        assertThat(template.signatureField().x()).isEqualTo(150);
        assertThat(template.signatureField().width()).isEqualTo(345);
        assertThat(template.width()).isEqualTo(345);
        assertThat(template.height()).isEqualTo(90);

        assertThat(template.fields().get(Fields.SIGNED_BY).value()).isEqualTo("Ministry");
        assertThat(template.fields().get(Fields.SIGNED_BY).labelShown()).isTrue();
        assertThat(template.fields().get(Fields.SIGNING_DATE).value()).isEqualTo("yyyy.MM.dd HH:mm:ss ZZ");
        assertThat(template.fields().get(Fields.REASON).position()).as("laid out like a configured template")
                .isNotNull();
        assertThat(template.fields().get(Fields.COMPANY_LOGO).value()).isEqualTo(LOGO);
    }

    @Test
    void dropsAFieldTheRowSwitchedOff() throws Exception {
        assertThat(codec.fromJson(ASCERTIA_ROW).fields()).doesNotContainKey(Fields.LOCATION);
    }

    @Test
    void keepsADisabledTemplateDisabled() throws Exception {
        String row = "{\"template_id\":\"Emad\",\"enabled\":false,\"company_logo\":{\"enabled\":true,\"value\":\""
                + LOGO + "\"}}";
        AppearanceTemplate template = codec.fromJson(row);

        assertThat(template.isEnabled()).isFalse();
        assertThat(template.fields()).containsKey(Fields.COMPANY_LOGO);
    }

    @Test
    void neverReadsAnImageValueAsAFilePath(@TempDir Path dir) throws Exception {
        Path secret = Files.writeString(dir.resolve("secret.txt"), "not for callers");
        String row = "{\"template_id\":\"probe\",\"enabled\":true,\"company_logo\":{\"enabled\":true,\"value\":"
                + mapper.writeValueAsString(secret.toAbsolutePath().toString()) + "}}";
        String fileAsBase64 = Base64.getEncoder().encodeToString(Files.readAllBytes(secret));

        AppearanceTemplate.Field logo = codec.fromJson(row).fields().get(Fields.COMPANY_LOGO);

        assertThat(logo == null ? null : logo.value()).isNotEqualTo(fileAsBase64);
    }

    @Test
    void writesTheShapeTheAscertiaOrchestratorReads() throws Exception {
        JsonNode written = mapper.readTree(codec.toJson(codec.fromJson(ASCERTIA_ROW)));

        assertThat(written.path("template_id").asText()).isEqualTo("Test_Nbi");
        assertThat(written.path("enabled").asBoolean()).isTrue();
        assertThat(written.path("signed_by").path("enabled").asBoolean()).isTrue();
        assertThat(written.path("signed_by").path("include_label").asBoolean()).isTrue();
        assertThat(written.path("signed_by").path("value").asText()).isEqualTo("Ministry");
        assertThat(written.path("company_logo").path("enabled").asBoolean()).isTrue();
        assertThat(written.path("company_logo").path("value").asText()).isEqualTo(LOGO);
        assertThat(written.path("signature_field").path("x").asInt()).isEqualTo(150);
        assertThat(written.path("signature_field").path("page_no").asInt()).isEqualTo(1);
        assertThat(written.path("background_color").path("a").asDouble()).isEqualTo(0.5);
        assertThat(written.has("fields")).as("no product-specific keys in a shared row").isFalse();
    }

    @Test
    void survivesARoundTrip() throws Exception {
        AppearanceTemplate first = codec.fromJson(ASCERTIA_ROW);
        AppearanceTemplate second = codec.fromJson(codec.toJson(first));

        assertThat(second.templateId()).isEqualTo(first.templateId());
        assertThat(second.signatureField()).isEqualTo(first.signatureField());
        assertThat(second.fields().keySet()).containsAll(
                java.util.List.of(Fields.SIGNED_BY, Fields.SIGNING_DATE, Fields.REASON, Fields.COMPANY_LOGO));
        assertThat(second.fields().get(Fields.REASON).value()).isEqualTo("Approved");
    }

    @Test
    void readsThisProductsOwnShapeUnchanged() throws Exception {
        String native_ = """
                {"template_id":"mine","fields":{"signed_by":{"include":true,"label":"By","show_label":true}}}
                """;
        AppearanceTemplate template = codec.fromJson(native_);

        assertThat(codec.isAscertiaShape(mapper.readTree(native_))).isFalse();
        assertThat(template.fields().get(Fields.SIGNED_BY).label()).isEqualTo("By");
    }

    @Test
    void writesNoPlacementForATemplateThatHasNone() throws Exception {
        AppearanceTemplate unplaced = new AppearanceTemplate("free", null, null, true, 300, 100, null, null,
                null, null, Map.of(Fields.SIGNED_BY,
                        new AppearanceTemplate.Field(true, "By", true, null, null, null, null)), null, null);

        assertThat(mapper.readTree(codec.toJson(unplaced)).has("signature_field")).isFalse();
    }
}
