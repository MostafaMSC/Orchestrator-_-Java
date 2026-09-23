package iq.twokeyok.orchestrator.appearance;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A signature appearance template as stored in
 * {@code orchestrator.appearances.store-path}, one JSON file per template.
 *
 * <p>This is also the shape returned by
 * {@code GET /orchestrator/service/signing/appearances/list}, so a business
 * application can render a picker and then send back a {@code template_id}.</p>
 *
 * @param templateId  stable id used in {@code signature_appearance.template_id}
 * @param name        human readable name for pickers
 * @param description free form description
 * @param width       appearance box width in points
 * @param height      appearance box height in points
 * @param border      optional border around the appearance
 * @param backgroundColor optional background fill
 * @param textFont    default font for every text field of the template
 * @param signatureField default placement of the box on the page
 * @param fields      the appearance fields, keyed by canonical name
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AppearanceTemplate(
        String templateId,
        String name,
        String description,
        Boolean enabled,
        Integer width,
        Integer height,
        Border border,
        Color backgroundColor,
        Font textFont,
        Box signatureField,
        Map<String, Field> fields) {

    public AppearanceTemplate {
        fields = fields == null ? new LinkedHashMap<>() : new LinkedHashMap<>(fields);
        width = width == null ? 463 : width;
        height = height == null ? 250 : height;
        enabled = enabled == null || enabled;
    }

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Border(Boolean show, Color color) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Color(Integer r, Integer g, Integer b, Double a) {

        public int red() {
            return r == null ? 0 : clamp(r);
        }

        public int green() {
            return g == null ? 0 : clamp(g);
        }

        public int blue() {
            return b == null ? 0 : clamp(b);
        }

        private static int clamp(int value) {
            return Math.max(0, Math.min(255, value));
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Font(String name, Integer size, Color color) {

        public String fontName() {
            return name == null || name.isBlank() ? "Arial" : name;
        }

        public int fontSize() {
            return size == null || size <= 0 ? 10 : size;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Box(Integer x, Integer y, Integer width, Integer height, Integer pageNo) {
    }

    /**
     * One field inside the appearance box.
     *
     * @param include  render this field at all
     * @param label    label printed before the value
     * @param showLabel print the label
     * @param value    default value; a request may override it when the client is
     *                 allowed to
     * @param position placement inside the appearance box
     * @param font     per-field font, falling back to the template font
     * @param imageName file name recorded in the appearance for image fields
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Field(
            Boolean include,
            String label,
            Boolean showLabel,
            String value,
            Box position,
            Font font,
            String imageName) {

        public boolean included() {
            return include == null || include;
        }

        public boolean labelShown() {
            return showLabel != null && showLabel;
        }
    }

    /** Canonical field keys understood by the orchestrator. */
    public static final class Fields {
        public static final String SIGNED_BY = "signed_by";
        /**
         * Carried on the template but never drawn: the ADSS appearance document
         * has no role field, so the value becomes the signature's signer role.
         */
        public static final String SIGNER_ROLE = "signer_role";
        public static final String REASON = "reason";
        public static final String LOCATION = "location";
        public static final String SIGNING_DATE = "signing_date";
        public static final String CONTACT_INFO = "contact_info";
        public static final String COMPANY_LOGO = "company_logo";
        public static final String HAND_SIGNATURE = "hand_signature";

        private Fields() {
        }
    }
}
