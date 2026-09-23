package iq.twokeyok.orchestrator.ops;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * {@code --verify-pdf <file>} — checks that a PDF really carries a digital
 * signature, and that the signature actually verifies over the document bytes.
 *
 * <p>This exists because "the API returned 200" is not evidence of a signature.
 * The inspector opens the signature dictionary, recomputes the signed content
 * from the {@code /ByteRange}, and cryptographically verifies the CMS blob
 * against the signer certificate embedded in it. It also reports whether the
 * ByteRange covers the whole file, whether a signature timestamp is present
 * (T / LTA levels) and whether the document carries a {@code /DSS} dictionary
 * (LT / LTV validation material).</p>
 *
 * <p>It verifies the <em>signature</em>, not the <em>trust chain</em>: it does
 * not check revocation or that the issuer is trusted. Use the ADSS Verification
 * Service for a full trust decision.</p>
 */
public final class PdfSignatureInspector {

    /** A PAdES-LTA document timestamp, as opposed to a document signature. */
    private static final String TIMESTAMP_SUBFILTER = "ETSI.RFC3161";

    private PdfSignatureInspector() {
    }

    /** @return process exit code: 0 when at least one signature verifies */
    public static int inspect(String path) {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        File file = new File(path);
        if (!file.isFile()) {
            System.out.println("  FAIL   no such file: " + file.getAbsolutePath());
            return 1;
        }

        List<String> out = new ArrayList<>();
        out.add("");
        out.add("PDF signature verification");
        out.add("==========================");
        out.add("  File      : " + file.getAbsolutePath());
        out.add("  Size      : " + file.length() + " bytes");

        try {
            byte[] bytes = Files.readAllBytes(file.toPath());
            try (PDDocument document = PDDocument.load(file)) {
                List<PDSignature> signatures = document.getSignatureDictionaries();
                if (signatures.isEmpty()) {
                    out.add("  Signatures: 0");
                    out.add("");
                    out.add("  RESULT    : FAIL — the document carries no signature dictionary.");
                    out.forEach(System.out::println);
                    return 1;
                }

                out.add("  Signatures: " + signatures.size());
                boolean hasDss = document.getDocumentCatalog().getCOSObject()
                        .getDictionaryObject(COSName.getPDFName("DSS")) != null;

                boolean allVerified = true;
                int documentSignatures = 0;
                int documentTimestamps = 0;
                int index = 0;
                for (PDSignature signature : signatures) {
                    index++;
                    boolean isTimestamp = TIMESTAMP_SUBFILTER.equals(signature.getSubFilter());
                    out.add("");
                    out.add("  --- " + (isTimestamp ? "Document timestamp " : "Signature ") + index + " ---");
                    out.add("  Field     : " + nullSafe(signature.getName()));
                    out.add("  Filter    : " + nullSafe(signature.getFilter()));
                    out.add("  SubFilter : " + nullSafe(signature.getSubFilter()));
                    if (!isTimestamp) {
                        out.add("  Reason    : " + nullSafe(signature.getReason()));
                        out.add("  Location  : " + nullSafe(signature.getLocation()));
                    }
                    out.add("  Signed at : " + (signature.getSignDate() == null
                            ? "-" : signature.getSignDate().getTime()));

                    if (isTimestamp) {
                        documentTimestamps++;
                        allVerified &= verifyDocumentTimestamp(signature, bytes, out);
                    } else {
                        documentSignatures++;
                        allVerified &= verifyDetachedSignature(signature, bytes, out);
                    }
                }

                out.add("");
                out.add("  ByteRange covers whole file : " + (coversWholeFile(signatures, bytes.length)
                        ? "yes" : "NO — content exists outside the signed ranges"));
                out.add("  /DSS validation material    : " + (hasDss ? "present (LT / LTV)" : "absent"));
                out.add("  Document signatures         : " + documentSignatures);
                out.add("  Document timestamps         : " + documentTimestamps
                        + (documentTimestamps > 0 ? "  (PAdES-LTA)" : ""));
                out.add("");

                boolean pass = allVerified && documentSignatures > 0;
                out.add("  RESULT    : " + (pass
                        ? "PASS — the document is digitally signed and every signature verifies."
                        : documentSignatures == 0
                                ? "FAIL — the document carries only timestamps, no signature."
                                : "FAIL — a signature is present but did not verify."));
                out.forEach(System.out::println);
                return pass ? 0 : 1;
            }
        } catch (Exception e) {
            out.add("");
            out.add("  RESULT    : FAIL — cannot read the document: " + e);
            out.forEach(System.out::println);
            return 1;
        }
    }

    /**
     * A PAdES-LTA document timestamp is an RFC 3161 token, not a detached
     * signature: its CMS <em>encapsulates</em> the TSTInfo, and what ties it to
     * the document is the message imprint, which must equal the digest of the
     * bytes the ByteRange covers. Verifying it as a detached signature fails
     * every time, which is wrong rather than informative.
     */
    private static boolean verifyDocumentTimestamp(PDSignature signature, byte[] bytes, List<String> out) {
        try {
            byte[] contents = signature.getContents(bytes);
            byte[] signedContent = signature.getSignedContent(bytes);

            TimeStampToken token = new TimeStampToken(new CMSSignedData(contents));
            TimeStampTokenInfo info = token.getTimeStampInfo();

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matches =
                    token.getCertificates().getMatches(token.getSID());
            if (matches.isEmpty()) {
                out.add("  Verified  : FAIL (TSA certificate not embedded)");
                return false;
            }
            X509CertificateHolder tsa = matches.iterator().next();
            out.add("  TSA DN    : " + tsa.getSubject());
            out.add("  Issuer DN : " + tsa.getIssuer());
            out.add("  GenTime   : " + info.getGenTime());
            out.add("  Policy    : " + info.getPolicy().getId());

            token.validate(new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(tsa));

            // The token only protects the document if its imprint matches it.
            String digestOid = info.getMessageImprintAlgOID().getId();
            MessageDigest digest = MessageDigest.getInstance(digestOid, BouncyCastleProvider.PROVIDER_NAME);
            boolean imprintMatches =
                    Arrays.equals(info.getMessageImprintDigest(), digest.digest(signedContent));

            out.add("  Imprint   : " + (imprintMatches
                    ? "matches the document bytes" : "DOES NOT match the document bytes"));
            out.add("  Verified  : " + (imprintMatches
                    ? "PASS (timestamp token is valid and covers this document)"
                    : "FAIL (timestamp does not cover this document)"));
            return imprintMatches;
        } catch (Exception e) {
            out.add("  Verified  : FAIL (" + e.getMessage() + ")");
            return false;
        }
    }

    /** Verifies one signature's CMS blob against the bytes its ByteRange covers. */
    private static boolean verifyDetachedSignature(PDSignature signature, byte[] bytes, List<String> out) {
        try {
            byte[] contents = signature.getContents(bytes);
            byte[] signedContent = signature.getSignedContent(bytes);
            if (contents == null || contents.length == 0) {
                out.add("  Verified  : FAIL (empty /Contents)");
                return false;
            }

            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), contents);
            Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
            if (signers.isEmpty()) {
                out.add("  Verified  : FAIL (no SignerInfo in the CMS structure)");
                return false;
            }

            boolean verified = true;
            for (SignerInformation signer : signers) {
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> matches =
                        cms.getCertificates().getMatches(signer.getSID());
                if (matches.isEmpty()) {
                    out.add("  Verified  : FAIL (signer certificate not embedded)");
                    verified = false;
                    continue;
                }
                X509CertificateHolder holder = matches.iterator().next();
                out.add("  Signer DN : " + holder.getSubject());
                out.add("  Issuer DN : " + holder.getIssuer());
                out.add("  Serial    : " + holder.getSerialNumber().toString(16));
                out.add("  Cert valid: " + holder.getNotBefore() + "  ..  " + holder.getNotAfter());
                out.add("  Digest alg: " + signer.getDigestAlgOID());

                boolean ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(new JcaX509CertificateConverter()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .getCertificate(holder)));
                out.add("  Verified  : " + (ok ? "PASS (signature is valid over the document bytes)" : "FAIL"));
                out.add("  Timestamp : " + (hasSignatureTimestamp(signer) ? "present (T / LTA)" : "absent"));
                verified &= ok;
            }
            return verified;
        } catch (Exception e) {
            out.add("  Verified  : FAIL (" + e.getMessage() + ")");
            return false;
        }
    }

    /** A signature timestamp lives as an unsigned attribute on the SignerInfo. */
    private static boolean hasSignatureTimestamp(SignerInformation signer) {
        AttributeTable unsigned = signer.getUnsignedAttributes();
        return unsigned != null
                && unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null;
    }

    /**
     * A signature only protects the bytes inside its ByteRange. Content appended
     * outside every range is unsigned, which is how a "signed" PDF can still have
     * been altered.
     */
    private static boolean coversWholeFile(List<PDSignature> signatures, int length) {
        for (PDSignature signature : signatures) {
            int[] range = signature.getByteRange();
            if (range != null && range.length == 4 && range[2] + range[3] == length) {
                return true;
            }
        }
        return false;
    }

    private static String nullSafe(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }
}
