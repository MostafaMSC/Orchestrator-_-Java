package iq.twokeyok.orchestrator.signing.gosign;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cms.CMSSignedData;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * Finds the CMS signature in whatever the Go>Sign Service returned.
 *
 * <p>Which of the two forms arrives has not been confirmed with a physical
 * token, so neither is assumed: a body that begins {@code %PDF} is read as a
 * document and the newest signature's {@code /Contents} taken out of it,
 * anything else is tried as a CMS directly. Both are checked by parsing, so a
 * body that is neither - an error page, say - is reported as such instead of
 * being injected into a document.</p>
 */
public final class CmsExtractor {

    private CmsExtractor() {
    }

    public static byte[] extract(byte[] body) {
        if (body == null || body.length == 0) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID, "the response was empty");
        }
        return looksLikePdf(body) ? fromPdf(body) : asCms(body);
    }

    private static boolean looksLikePdf(byte[] body) {
        return body.length > 4 && body[0] == '%' && body[1] == 'P' && body[2] == 'D' && body[3] == 'F';
    }

    /**
     * The service assembled the signature into a document of its own - built
     * from the stub, so the document itself is of no use. Only the signature is
     * taken, and it is the one over our digest.
     */
    private static byte[] fromPdf(byte[] body) {
        try (PDDocument document = PDDocument.load(body)) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                        "the returned document carries no signature");
            }
            byte[] contents = signatures.get(signatures.size() - 1).getContents(body);
            return asCms(firstDerObject(contents));
        } catch (OrchestratorException e) {
            throw e;
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                    "the returned document cannot be read: " + e.getMessage());
        }
    }

    private static byte[] asCms(byte[] candidate) {
        try {
            CMSSignedData data = new CMSSignedData(candidate);
            if (data.getSignerInfos().size() == 0) {
                throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                        "the CMS carries no signer");
            }
            return candidate;
        } catch (OrchestratorException e) {
            throw e;
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                    "the response is neither a signed PDF nor a CMS signature ("
                            + candidate.length + " bytes)");
        }
    }

    /**
     * The signature out of a padded {@code /Contents}.
     *
     * <p>A {@code /Contents} is zero-filled to the size reserved for it, so the
     * padding has to go. Trimming trailing zeros is the obvious way and the
     * wrong one: a CMS ends in an RSA signature, whose last byte is zero often
     * enough, and trimming those eats part of the structure. So the first ASN.1
     * object is read instead and its own declared length decides where the
     * signature ends.</p>
     */
    private static byte[] firstDerObject(byte[] contents) {
        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(contents))) {
            ASN1Primitive first = asn1.readObject();
            if (first == null) {
                throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                        "the signature field is empty");
            }
            return first.getEncoded("DER");
        } catch (OrchestratorException e) {
            throw e;
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                    "the signature field does not hold an ASN.1 structure: " + e.getMessage());
        }
    }
}
