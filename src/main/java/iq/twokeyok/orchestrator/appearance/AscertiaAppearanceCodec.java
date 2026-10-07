package iq.twokeyok.orchestrator.appearance;

import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Field;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.AppearanceTemplateConfig;

/**
 * Converts between {@link AppearanceTemplate} and the JSON the Ascertia
 * Orchestrator keeps in its {@code appearancetemplate.signatureappearance}
 * column.
 *
 * <p>That JSON is the same shape as the appearances declared in
 * {@code orchestrator.yml}: one object per text field
 * ({@code {enabled, include_label, label, value}}), {@code company_logo} as
 * {@code {enabled, value}}, plus {@code text_font}, {@code background_color},
 * {@code signature_field} and {@code signature_text_position}. Reading it
 * therefore goes through {@link AppearanceLayout}, exactly as a configured
 * template does, and both orchestrators can share one table.</p>
 *
 * <p>Writing is lossy for what that shape cannot hold: per-field positions and
 * fonts, image file names and the border. The layout is recomputed from
 * {@code signature_text_position} when the row is read back.</p>
 */
@Component
public class AscertiaAppearanceCodec {

    /** Text fields in the order the Ascertia shape names them. */
    private static final List<String> TEXT_FIELDS = List.of(
            Fields.SIGNED_BY, Fields.SIGNER_ROLE, Fields.SIGNING_DATE, Fields.REASON,
            Fields.LOCATION, Fields.CONTACT_INFO, Fields.USER_INFO);
    private static final List<String> IMAGE_FIELDS = List.of(Fields.COMPANY_LOGO, Fields.HAND_SIGNATURE);

    private final ObjectMapper objectMapper;

    public AscertiaAppearanceCodec(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    // ------------------------------------------------------------------
    // Reading
    // ------------------------------------------------------------------

    /**
     * @param json a stored row, in the Ascertia shape or, for robustness, in
     *             this product's own template shape
     */
    public AppearanceTemplate fromJson(String json) throws JsonProcessingException {
        return fromNode(objectMapper.readTree(json));
    }

    public AppearanceTemplate fromNode(JsonNode node) throws JsonProcessingException {
        if (!isAscertiaShape(node)) {
            return objectMapper.treeToValue(node, AppearanceTemplate.class);
        }
        // Images from a row or a request are Base64 by definition; never paths.
        return AppearanceLayout.toTemplate(toConfig(node), null, false);
    }

    /**
     * The Ascertia shape names its fields at the top level as objects; this
     * product's shape keeps them under {@code fields}. A body with neither, such
     * as one carrying only an id and a box, reads the same either way.
     */
    public boolean isAscertiaShape(JsonNode node) {
        if (node == null || !node.isObject() || node.has("fields")) {
            return false;
        }
        if (node.has("signature_text_position")) {
            return true;
        }
        for (String key : TEXT_FIELDS) {
            if (node.path(key).isObject()) {
                return true;
            }
        }
        for (String key : IMAGE_FIELDS) {
            if (node.path(key).isObject()) {
                return true;
            }
        }
        return false;
    }

    private static AppearanceTemplateConfig toConfig(JsonNode node) {
        String templateId = text(node, "template_id");
        return new AppearanceTemplateConfig(
                templateId,
                text(node, "name"),
                text(node, "description"),
                node.path("enabled").asBoolean(true),
                node.hasNonNull("signature_text_position") ? node.get("signature_text_position").asText() : "BOTTOM",
                textField(node.get(Fields.SIGNED_BY)),
                textField(node.get(Fields.SIGNER_ROLE)),
                textField(node.get(Fields.SIGNING_DATE)),
                textField(node.get(Fields.REASON)),
                textField(node.get(Fields.LOCATION)),
                textField(node.get(Fields.CONTACT_INFO)),
                font(node.get("text_font")),
                color(node.hasNonNull("background_color") ? node.get("background_color")
                        : node.get("text_background_color")),
                signatureField(node.get("signature_field")),
                image(node.get(Fields.COMPANY_LOGO)),
                image(node.get(Fields.HAND_SIGNATURE)));
    }

    /** A field switched off with {@code enabled: false} is not drawn at all. */
    private static SigningProperties.TextField textField(JsonNode node) {
        if (node == null || !node.isObject() || !node.path("enabled").asBoolean(true)) {
            return null;
        }
        return new SigningProperties.TextField(
                node.path("include_label").asBoolean(false), text(node, "label"), text(node, "value"));
    }

    private static SigningProperties.Image image(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isTextual()) {
            return new SigningProperties.Image(node.asText(), null);
        }
        if (!node.isObject() || !node.path("enabled").asBoolean(true)) {
            return null;
        }
        return new SigningProperties.Image(text(node, "value"), text(node, "name"));
    }

    private static SigningProperties.Font font(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        String name = text(node, "name");
        int size = node.path("size").asInt(10);
        return new SigningProperties.Font(name == null ? "Helvetica" : name, size <= 0 ? 10 : size,
                color(node.get("color")));
    }

    private static SigningProperties.Color color(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        return new SigningProperties.Color(node.path("r").asInt(0), node.path("g").asInt(0),
                node.path("b").asInt(0), node.path("a").asDouble(1.0));
    }

    private static SigningProperties.SignatureField signatureField(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        int page = node.path("page_no").asInt(1);
        return new SigningProperties.SignatureField(text(node, "field_id"), page <= 0 ? 1 : page,
                node.path("x").asInt(0), node.path("y").asInt(0),
                node.path("width").asInt(0), node.path("height").asInt(0));
    }

    private static String text(JsonNode node, String key) {
        JsonNode value = node.get(key);
        return value == null || value.isNull() ? null : value.asText();
    }

    // ------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------

    public String toJson(AppearanceTemplate template) throws JsonProcessingException {
        return objectMapper.writeValueAsString(toNode(template));
    }

    public ObjectNode toNode(AppearanceTemplate template) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("template_id", template.templateId());
        putIfPresent(node, "name", template.name());
        putIfPresent(node, "description", template.description());
        node.put("enabled", template.isEnabled());

        for (String key : TEXT_FIELDS) {
            Field field = template.fields().get(key);
            if (field == null) {
                continue;
            }
            ObjectNode out = node.putObject(key);
            out.put("enabled", field.included());
            out.put("include_label", field.labelShown());
            putIfPresent(out, "label", field.label());
            putIfPresent(out, "value", field.value());
        }
        for (String key : IMAGE_FIELDS) {
            Field field = template.fields().get(key);
            if (field == null || field.value() == null || field.value().isBlank()) {
                continue;
            }
            ObjectNode out = node.putObject(key);
            out.put("enabled", field.included());
            out.put("value", field.value());
        }

        if (template.textFont() != null) {
            ObjectNode font = node.putObject("text_font");
            font.put("name", template.textFont().fontName());
            font.put("size", template.textFont().fontSize());
            if (template.textFont().color() != null) {
                putColor(font.putObject("color"), template.textFont().color());
            }
        }
        if (template.backgroundColor() != null) {
            putColor(node.putObject("background_color"), template.backgroundColor());
        }

        // The Ascertia shape sizes the appearance by its signature field. A
        // template without a placement is written without one rather than
        // pinned to the page origin; it then needs signature_field per request.
        AppearanceTemplate.Box box = template.signatureField();
        if (box != null && box.x() != null && box.y() != null) {
            ObjectNode field = node.putObject("signature_field");
            field.put("page_no", box.pageNo() == null ? 1 : box.pageNo());
            field.put("x", box.x());
            field.put("y", box.y());
            field.put("width", box.width() != null ? box.width() : template.width());
            field.put("height", box.height() != null ? box.height() : template.height());
        }
        return node;
    }

    private static void putColor(ObjectNode out, AppearanceTemplate.Color color) {
        out.put("r", color.red());
        out.put("g", color.green());
        out.put("b", color.blue());
        out.put("a", color.a() == null ? 1.0 : color.a());
    }

    private static void putIfPresent(ObjectNode node, String key, String value) {
        if (value != null) {
            node.put(key, value);
        }
    }
}
