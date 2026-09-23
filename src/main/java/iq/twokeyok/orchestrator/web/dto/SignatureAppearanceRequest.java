package iq.twokeyok.orchestrator.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The {@code signature_appearance} form field of {@code POST /service/sign},
 * exactly as documented in the TwoKeyOk MiddleWare API guide.
 *
 * <p>Every member is optional: whatever is absent falls back to the appearance
 * template, and the template falls back to the orchestrator defaults.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignatureAppearanceRequest(
        String templateId,
        TextField signedBy,
        TextField signerRole,
        TextField signingDate,
        TextField reason,
        TextField location,
        TextField contactInfo,
        Font textFont,
        Color backgroundColor,
        Box signatureField,
        Image companyLogo,
        /** Orchestrator extension: the signer's scanned handwritten signature. */
        Image handSignature) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record TextField(String label, Boolean includeLabel, String value) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Font(String name, Integer size, Color color) {
    }

    /** RGB 0-255 with an optional alpha in 0.0-1.0. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Color(Integer r, Integer g, Integer b, Double a) {
    }

    /** Signature box on the page, in PDF user-space points from the bottom left. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Box(Integer x, Integer y, Integer width, Integer height, Integer pageNo) {

        public boolean complete() {
            return x != null && y != null && width != null && height != null;
        }
    }

    /** Base64 encoded image payload. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Image(String value, String name) {
    }
}
