package iq.twokeyok.orchestrator.appearance;

/**
 * The outcome of merging a request's {@code signature_appearance} onto a stored
 * template: everything the ADSS request needs, already decided.
 *
 * @param templateId     template the appearance was built from
 * @param appearanceXml  ADSS {@code SignatureAppearanceSettings} document
 * @param signedBy       value for {@code setSignedBy}
 * @param signerRole     value for {@code setSignerRole}
 * @param reason         value for {@code setSigningReason}
 * @param location       value for {@code setSigningLocation}
 * @param contactInfo    value for {@code setContactInfo}
 * @param companyLogo    decoded logo image, or {@code null}
 * @param handSignature  decoded handwritten signature image, or {@code null}
 * @param box            signature box on the page, or {@code null} to let the
 *                       ADSS profile decide
 */
public record ResolvedAppearance(
        String templateId,
        byte[] appearanceXml,
        String signedBy,
        String signerRole,
        String reason,
        String location,
        String contactInfo,
        byte[] companyLogo,
        byte[] handSignature,
        SignatureBox box) {

    /** Signature box in PDF points, origin at the bottom-left of the page. */
    public record SignatureBox(int x, int y, int width, int height, int pageNo) {

        public int x2() {
            return x + width;
        }

        public int y2() {
            return y + height;
        }
    }
}
