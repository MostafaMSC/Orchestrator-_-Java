package iq.twokeyok.orchestrator.appearance;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Box;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Color;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Field;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Font;

/**
 * Renders the ADSS {@code SignatureAppearanceSettings} XML consumed by
 * {@code PdfSigningRequest.setSignatureAppearance(byte[])}.
 *
 * <p>The element and attribute names follow the appearance document shipped with
 * the ADSS Client SDK ({@code API/samples/data/signing/appearance.xml}).</p>
 */
@Component
public class AppearanceXmlWriter {

    /** Canonical orchestrator field key to the ADSS appearance field name. */
    private static final Map<String, String> ADSS_FIELD_NAMES = Map.of(
            Fields.SIGNED_BY, "SIGNED_BY",
            Fields.REASON, "SIGNING_REASON",
            Fields.LOCATION, "SIGNING_LOCATION",
            Fields.SIGNING_DATE, "SIGNING_DATE",
            Fields.CONTACT_INFO, "CONTACT_INFO",
            Fields.COMPANY_LOGO, "COMPANY_LOGO",
            Fields.HAND_SIGNATURE, "HAND_SIGNATURE");

    private static final Map<String, String> DEFAULT_LABELS = Map.of(
            Fields.SIGNED_BY, "Signed By",
            Fields.REASON, "Reason",
            Fields.LOCATION, "Location",
            Fields.SIGNING_DATE, "Signing Date",
            Fields.CONTACT_INFO, "Contact Info",
            Fields.COMPANY_LOGO, "Company Logo",
            Fields.HAND_SIGNATURE, "Hand Signature");

    private static boolean isImageField(String key) {
        return Fields.COMPANY_LOGO.equals(key) || Fields.HAND_SIGNATURE.equals(key);
    }

    /**
     * @param template  the template being rendered
     * @param values    effective value per canonical field key; a {@code null} or
     *                  blank value drops the field from the appearance
     * @param overrides per-field label / showLabel overrides coming from the
     *                  request, keyed by canonical field name (may be empty)
     */
    public byte[] write(AppearanceTemplate template,
                        Map<String, String> values,
                        Map<String, LabelOverride> overrides) {
        StringBuilder xml = new StringBuilder(4096);
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>");
        xml.append("<SignatureAppearanceSettings>");
        xml.append("<SignatureAppearance discription=\"")
                .append(escape(nullToEmpty(template.description())))
                .append("\" height=\"").append(template.height())
                .append("\" name=\"").append(escape(template.templateId()))
                .append("\" width=\"").append(template.width()).append("\">");

        appendBorder(xml, template);
        appendBackground(xml, template);

        xml.append("<Fields>");
        for (Map.Entry<String, String> entry : orderedFields(template, values).entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            Field field = template.fields().get(key);
            if (field == null || !field.included() || value == null || value.isBlank()) {
                continue;
            }
            appendField(xml, template, key, field, value,
                    overrides.getOrDefault(key, LabelOverride.NONE));
        }
        xml.append("</Fields>");
        xml.append("</SignatureAppearance>");
        xml.append("</SignatureAppearanceSettings>");
        return xml.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Keeps the template's declaration order, which is what positions the fields. */
    private static Map<String, String> orderedFields(AppearanceTemplate template, Map<String, String> values) {
        Map<String, String> ordered = new LinkedHashMap<>();
        template.fields().keySet().forEach(key -> ordered.put(key, values.get(key)));
        return ordered;
    }

    private void appendField(StringBuilder xml,
                             AppearanceTemplate template,
                             String key,
                             Field field,
                             String value,
                             LabelOverride override) {
        String adssName = ADSS_FIELD_NAMES.get(key);
        if (adssName == null) {
            return;
        }
        boolean showLabel = override.showLabel() == null ? field.labelShown() : override.showLabel();
        String label = override.label() != null ? override.label()
                : field.label() != null ? field.label()
                : DEFAULT_LABELS.getOrDefault(key, "");

        xml.append("<Field border=\"false\" labelName=\"").append(escape(stripTrailingSeparator(label)))
                .append("\" name=\"").append(adssName)
                .append("\" showLabel=\"").append(showLabel).append("\">");
        appendPosition(xml, field.position());
        xml.append("<Value>").append(escape(value)).append("</Value>");
        if (isImageField(key)) {
            xml.append("<ImageName>")
                    .append(escape(field.imageName() == null ? adssName + ".png" : field.imageName()))
                    .append("</ImageName>");
        } else {
            appendFont(xml, field.font() != null ? field.font() : template.textFont());
        }
        xml.append("</Field>");
    }

    private static void appendPosition(StringBuilder xml, Box position) {
        if (position == null) {
            return;
        }
        xml.append("<Position height=\"").append(orZero(position.height()))
                .append("\" width=\"").append(orZero(position.width()))
                .append("\" x=\"").append(orZero(position.x()))
                .append("\" y=\"").append(orZero(position.y()))
                .append("\"/>");
    }

    private static void appendFont(StringBuilder xml, Font font) {
        Font effective = font == null ? new Font("Arial", 10, null) : font;
        xml.append("<Font name=\"").append(escape(effective.fontName()))
                .append("\" size=\"").append(effective.fontSize()).append("\">");
        appendColor(xml, effective.color());
        xml.append("</Font>");
    }

    private static void appendColor(StringBuilder xml, Color color) {
        Color effective = color == null ? new Color(0, 0, 0, null) : color;
        xml.append("<Color B=\"").append(effective.blue())
                .append("\" G=\"").append(effective.green())
                .append("\" R=\"").append(effective.red()).append("\"/>");
    }

    private static void appendBorder(StringBuilder xml, AppearanceTemplate template) {
        AppearanceTemplate.Border border = template.border();
        boolean show = border != null && Boolean.TRUE.equals(border.show());
        xml.append("<Border showBorder=\"").append(show).append("\">");
        appendColor(xml, border == null ? null : border.color());
        xml.append("</Border>");
    }

    private static void appendBackground(StringBuilder xml, AppearanceTemplate template) {
        if (template.backgroundColor() == null) {
            return;
        }
        xml.append("<BackgroundColor>");
        appendColor(xml, template.backgroundColor());
        xml.append("</BackgroundColor>");
    }

    /**
     * ADSS renders {@code labelName} followed by its own separator, so a label
     * configured as {@code "Signed By: "} would print a double colon.
     */
    private static String stripTrailingSeparator(String label) {
        String trimmed = label == null ? "" : label.trim();
        while (trimmed.endsWith(":")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1).trim();
        }
        return trimmed;
    }

    private static int orZero(Integer value) {
        return value == null ? 0 : value;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&apos;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    /** Per-field label overrides carried by {@code signature_appearance}. */
    public record LabelOverride(String label, Boolean showLabel) {

        public static final LabelOverride NONE = new LabelOverride(null, null);
    }
}
