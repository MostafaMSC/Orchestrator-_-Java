package iq.twokeyok.orchestrator.signing;

import java.util.Locale;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * Maps the ETSI signature levels used in the reference configuration
 * ({@code PAdES_BASELINE_LTA}, {@code PKCS7_LT}, …) onto the PAdES types the
 * ADSS Client SDK understands.
 *
 * <p>The SDK exposes only three upgrade types — {@code PAdES-LTV},
 * {@code PAdES-LT} and {@code PAdES-B-LTA}. The B and T levels are not upgrade
 * requests at all: they are produced by the ADSS signing profile itself, so for
 * those this returns {@code null} and the profile decides.</p>
 *
 * <p>The literals are taken from the SDK constants rather than retyped. Note
 * that {@code PdfSigningRequest.PADES_LT} is {@code "PADES_LT"} while
 * {@code PdfSigningResponse.PADES_LT} is {@code "PAdES-LT"}; the hyphenated
 * spelling is the one that matches every other value the SDK sends, so that is
 * what is used here.</p>
 */
public final class PadesLevel {

    public static final String PADES_LTV = "PAdES-LTV";
    public static final String PADES_LT = "PAdES-LT";
    public static final String PADES_B_LTA = "PAdES-B-LTA";

    private PadesLevel() {
    }

    /**
     * @param level configured level, in either spelling
     * @return the SDK PAdES type, or {@code null} when the ADSS signing profile
     *         determines the level
     * @throws OrchestratorException when the level is not a PDF level at all
     */
    public static String toSdkType(String level) {
        if (level == null || level.isBlank()) {
            return null;
        }
        String normalised = level.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (normalised) {
            // Produced by the signing profile; nothing to request.
            case "PADES_BASELINE_B", "PADES_BASELINE_T",
                 "PKCS7_B", "PKCS7_T",
                 "PDF_NOT_ETSI", "NONE" -> null;

            case "PADES_BASELINE_LT", "PKCS7_LT", "PADES_LT" -> PADES_LT;
            case "PADES_BASELINE_LTA", "PKCS7_LTA", "PADES_B_LTA" -> PADES_B_LTA;
            case "PADES_LTV" -> PADES_LTV;

            default -> throw new OrchestratorException(ErrorCode.UNSUPPORTED_SIGNATURE_LEVEL, level);
        };
    }

    /** {@code true} when the level needs the verification and TSA services configured. */
    public static boolean requiresLongTermServices(String sdkType) {
        return sdkType != null;
    }

    public static final String ETSI_CADES_DETACHED = "ETSI.CAdES.detached";
    public static final String ADBE_PKCS7_DETACHED = "adbe.pkcs7.detached";

    /**
     * The SDK type that makes it write {@code /SubFilter /ETSI.CAdES.detached}
     * when it hashes locally without upgrading anything. The SDK selects PAdES
     * for any type containing {@code PAdES-B-}, and upgrades only for exactly
     * {@link #PADES_LT}, {@link #PADES_LTV} and {@link #PADES_B_LTA}.
     */
    public static final String SDK_PADES_BASELINE = "PAdES-B-B";

    /**
     * @param configured {@code sub_filter}, if set
     * @param level      configured {@code signature_level}
     * @return {@link #ETSI_CADES_DETACHED} or {@link #ADBE_PKCS7_DETACHED}
     */
    public static String subFilter(String configured, String level) {
        if (configured != null && !configured.isBlank()) {
            String value = configured.trim();
            if (value.equalsIgnoreCase(ETSI_CADES_DETACHED)) {
                return ETSI_CADES_DETACHED;
            }
            if (value.equalsIgnoreCase(ADBE_PKCS7_DETACHED)) {
                return ADBE_PKCS7_DETACHED;
            }
            throw new OrchestratorException(ErrorCode.UNSUPPORTED_SIGNATURE_LEVEL, "sub_filter " + value);
        }
        String normalised = level == null ? "" : level.trim().toUpperCase(Locale.ROOT);
        // A PKCS7 level, or one that is explicitly not ETSI, asks for the
        // Adobe form; every PAdES level is PAdES.
        return normalised.startsWith("PKCS7") || normalised.startsWith("PDF_NOT_ETSI")
                ? ADBE_PKCS7_DETACHED : ETSI_CADES_DETACHED;
    }
}
