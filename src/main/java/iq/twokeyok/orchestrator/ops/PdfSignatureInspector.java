package iq.twokeyok.orchestrator.ops;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import iq.twokeyok.orchestrator.signing.timestamp.OcspClient;

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
    /**
     * The legacy PKCS#7 form, where the digest of the byte range is carried
     * <em>inside</em> the SignedData instead of the signature being detached.
     * ADSS signing profiles configured for {@code adbe.pkcs7.sha1} produce it.
     */
    private static final String PKCS7_SHA1_SUBFILTER = "adbe.pkcs7.sha1";
    /** RFC 6960 id-pkix-ocsp-nocheck: a responder whose own status is not checked. */
    private static final ASN1ObjectIdentifier OCSP_NOCHECK = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5");

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
                COSBase dssBase = document.getDocumentCatalog().getCOSObject()
                        .getDictionaryObject(COSName.getPDFName("DSS"));
                boolean hasDss = dssBase != null;

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
                    if (!isTimestamp) {
                        out.add("  Visible   : " + describeVisibility(document, signature));
                        // The maths checking out is not the same as a reader
                        // accepting it: adbe.pkcs7.sha1 digests the document
                        // with SHA-1, and Acrobat has refused SHA-1 document
                        // signatures for years. A bare PASS here sent an
                        // operator looking for a bug in a correct file.
                        if (PKCS7_SHA1_SUBFILTER.equals(signature.getSubFilter())) {
                            out.add("  Standard  : legacy PKCS#7 with a SHA-1 document digest."
                                    + " Not a PAdES baseline signature, and Acrobat rejects SHA-1:"
                                    + " use an ADSS profile configured for ETSI.CAdES.detached");
                        }
                    }

                    if (isTimestamp) {
                        documentTimestamps++;
                        allVerified &= verifyDocumentTimestamp(signature, bytes, out);
                    } else {
                        documentSignatures++;
                        allVerified &= encapsulatesItsContent(signature, bytes)
                        ? verifyEncapsulatedSignature(signature, bytes, out)
                        : verifyDetachedSignature(signature, bytes, out,
                                PKCS7_SHA1_SUBFILTER.equals(signature.getSubFilter()));
                    }
                }

                out.add("");
                out.add("  ByteRange covers whole file : " + (coversWholeFile(signatures, bytes.length)
                        ? "yes" : "NO — content exists outside the signed ranges"));
                out.add("  /DSS validation material    : " + (hasDss ? "present (LT / LTV)" : "absent"));
                describeDss(dssBase, out);
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

    /**
     * Whether the CMS carries its content inside, which decides how it must be
     * verified.
     *
     * <p>Chosen from the structure rather than from {@code /SubFilter}, because
     * the two disagree in practice: ADSS has produced {@code adbe.pkcs7.sha1}
     * signatures both with an encapsulated digest and without one. Branching on
     * the label alone failed a valid detached signature that happened to carry
     * the legacy subfilter. The structure is what the verification actually
     * depends on, so it is what gets asked.</p>
     */
    private static boolean encapsulatesItsContent(PDSignature signature, byte[] bytes) {
        try {
            byte[] contents = signature.getContents(bytes);
            if (contents == null || contents.length == 0) {
                return false;
            }
            CMSSignedData cms = new CMSSignedData(contents);
            return cms.getSignedContent() != null && cms.getSignedContent().getContent() instanceof byte[];
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verifies a signature that encapsulates its content - the legacy
     * {@code adbe.pkcs7.sha1} form.
     *
     * <p>Here the SignedData <em>encapsulates</em> its content, and that content
     * is the SHA-1 digest of the byte range (PDF 1.7, 12.8.3.3) — the signature
     * covers the digest, not the document. Verifying it as a detached signature
     * compares {@code messageDigest} against the wrong bytes and fails on a
     * perfectly valid signature, which is what this method exists to avoid.</p>
     *
     * <p>So two things are checked: the SignerInfo over the encapsulated
     * content, and that the encapsulated digest really is the digest of this
     * document's byte range. Either one alone would be insufficient — the first
     * says nothing about which document was signed, the second nothing about
     * who signed it.</p>
     */
    private static boolean verifyEncapsulatedSignature(PDSignature signature, byte[] bytes, List<String> out) {
        try {
            byte[] contents = signature.getContents(bytes);
            byte[] signedContent = signature.getSignedContent(bytes);
            if (contents == null || contents.length == 0) {
                out.add("  Verified  : FAIL (empty /Contents)");
                return false;
            }

            CMSSignedData cms = new CMSSignedData(contents);
            Object encapsulated = cms.getSignedContent() == null ? null : cms.getSignedContent().getContent();
            if (!(encapsulated instanceof byte[] embeddedDigest)) {
                out.add("  Verified  : FAIL (no encapsulated content in an adbe.pkcs7.sha1 signature)");
                return false;
            }

            boolean coversDocument = Arrays.equals(embeddedDigest,
                    MessageDigest.getInstance("SHA-1").digest(signedContent));
            out.add("  Imprint   : " + (coversDocument
                    ? "matches the document bytes"
                    : "DOES NOT match the document bytes"));

            Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
            if (signers.isEmpty()) {
                out.add("  Verified  : FAIL (no SignerInfo in the CMS structure)");
                return false;
            }

            boolean verified = coversDocument;
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
                describeSigner(holder, signer, out);

                boolean ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(new JcaX509CertificateConverter()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .getCertificate(holder)));
                out.add("  Verified  : " + (ok && coversDocument
                        ? "PASS (legacy PKCS#7, signature valid over the document digest)"
                        : "FAIL"));
                out.add("  Timestamp : " + (hasSignatureTimestamp(signer) ? "present (T / LTA)" : "absent"));
                verified &= ok;
            }
            return verified;
        } catch (Exception e) {
            out.add("  Verified  : FAIL (" + e.getMessage() + ")");
            return false;
        }
    }

    private static void describeSigner(X509CertificateHolder holder, SignerInformation signer, List<String> out) {
        out.add("  Signer DN : " + holder.getSubject());
        out.add("  Issuer DN : " + holder.getIssuer());
        out.add("  Serial    : " + holder.getSerialNumber().toString(16));
        out.add("  Cert valid: " + holder.getNotBefore() + "  ..  " + holder.getNotAfter());
        out.add("  Digest alg: " + signer.getDigestAlgOID());
    }

    /**
     * Verifies a signature whose content is not carried inside the CMS.
     *
     * <p>Normally the content is the byte range itself. Under
     * {@code adbe.pkcs7.sha1} it is the <em>SHA-1 digest</em> of the byte range
     * (PDF 1.7, 12.8.3.3), and ADSS sometimes computes the signed attributes
     * over that digest while omitting it from the structure. Verifying such a
     * signature against the document bytes compares {@code messageDigest}
     * against the wrong input and fails on a valid signature, so the digest is
     * reconstructed and supplied as the content.</p>
     *
     * @param legacyDigestContent the signed content is the SHA-1 digest of the
     *                            byte range rather than the byte range
     */
    private static boolean verifyDetachedSignature(PDSignature signature, byte[] bytes, List<String> out,
                                                   boolean legacyDigestContent) {
        try {
            byte[] contents = signature.getContents(bytes);
            byte[] signedContent = signature.getSignedContent(bytes);
            if (contents == null || contents.length == 0) {
                out.add("  Verified  : FAIL (empty /Contents)");
                return false;
            }
            if (legacyDigestContent) {
                signedContent = MessageDigest.getInstance("SHA-1").digest(signedContent);
                out.add("  Imprint   : signature covers the SHA-1 digest of the document bytes");
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
                describeSigner(holder, signer, out);

                boolean ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(new JcaX509CertificateConverter()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .getCertificate(holder)));
                out.add("  Verified  : " + (ok
                        ? legacyDigestContent
                                ? "PASS (legacy PKCS#7, signature valid over the document digest)"
                                : "PASS (signature is valid over the document bytes)"
                        : "FAIL"));
                out.add("  Timestamp : " + (hasSignatureTimestamp(signer) ? "present (T / LTA)" : "absent"));
                verified &= ok;
            }
            return verified;
        } catch (Exception e) {
            out.add("  Verified  : FAIL (" + e.getMessage() + ")");
            return false;
        }
    }

    /**
     * Whether this signature is drawn on a page, and where.
     *
     * <p>Worth reporting because "the appearance is configured" and "the
     * appearance was rendered" are different things, and under hash signing they
     * come apart: ADSS never sees the document, so an appearance named by
     * {@code server_side_id} is not drawn by anything. A signature is visible
     * when its widget has a non-empty rectangle <em>and</em> a normal appearance
     * stream - a zero-size rectangle is the conventional invisible signature,
     * and a rectangle with no appearance stream draws nothing.</p>
     */
    private static String describeVisibility(PDDocument document, PDSignature signature) {
        try {
            PDAcroForm form = document.getDocumentCatalog().getAcroForm();
            if (form == null) {
                return "no (document has no AcroForm)";
            }
            for (PDField field : form.getFieldTree()) {
                if (!(field instanceof PDSignatureField signatureField)) {
                    continue;
                }
                PDSignature found = signatureField.getSignature();
                if (found == null || !found.getCOSObject().equals(signature.getCOSObject())) {
                    continue;
                }
                PDAnnotationWidget widget = signatureField.getWidgets().isEmpty()
                        ? null : signatureField.getWidgets().get(0);
                if (widget == null || widget.getRectangle() == null) {
                    return "no (field has no widget)";
                }
                PDRectangle rect = widget.getRectangle();
                boolean placed = rect.getWidth() > 0 && rect.getHeight() > 0;
                boolean drawn = widget.getAppearance() != null
                        && widget.getAppearance().getNormalAppearance() != null;
                String where = "page %s, %.0f,%.0f %.0fx%.0f".formatted(
                        pageOf(document, widget), rect.getLowerLeftX(), rect.getLowerLeftY(),
                        rect.getWidth(), rect.getHeight());
                if (placed && drawn) {
                    return "yes - " + where;
                }
                if (placed) {
                    return "no - box at " + where + " but no appearance stream";
                }
                return "no (invisible: zero-size rectangle)";
            }
            return "no (no signature field references this signature)";
        } catch (Exception e) {
            return "unknown (" + e.getMessage() + ")";
        }
    }

    private static String pageOf(PDDocument document, PDAnnotationWidget widget) {
        if (widget.getPage() == null) {
            return "?";
        }
        for (int i = 0; i < document.getNumberOfPages(); i++) {
            if (document.getPage(i).getCOSObject().equals(widget.getPage().getCOSObject())) {
                return String.valueOf(i + 1);
            }
        }
        return "?";
    }

    /**
     * What the {@code /DSS} actually holds, not merely that it exists.
     *
     * <p>"present" is not enough to judge a long-term signature: PAdES-LT
     * requires revocation data for <em>every</em> certificate in every chain,
     * and a count of responses cannot say which certificates they answer for.
     * So each certificate is listed with the response that covers it, the
     * status that response reports, and the responder that signed it.</p>
     *
     * <p>{@code /VRI} keys the same material per signature, by the hex SHA-1 of
     * each signature's {@code /Contents}. It is optional - ETSI EN 319 142-1
     * lets a reader take what it needs from {@code /Certs} and {@code /OCSPs}
     * directly - so an empty one is reported plainly rather than as a fault.</p>
     */
    private static void describeDss(COSBase dssBase, List<String> out) {
        if (!(dssBase instanceof COSDictionary dss)) {
            return;
        }
        out.add("    certificates              : " + arraySize(dss, "Certs"));
        out.add("    OCSP responses            : " + arraySize(dss, "OCSPs"));
        out.add("    CRLs                      : " + arraySize(dss, "CRLs"));
        describeVri(dss, out);
        describeRevocationCoverage(dss, out);
    }

    private static void describeVri(COSDictionary dss, List<String> out) {
        String optional = "  (optional; readers may use /Certs and /OCSPs directly)";
        if (!(dss.getDictionaryObject(COSName.getPDFName("VRI")) instanceof COSDictionary vri)) {
            out.add("    per-signature (/VRI)      : absent" + optional);
            return;
        }
        int entries = vri.keySet().size();
        out.add("    per-signature (/VRI)      : " + entries + " entr" + (entries == 1 ? "y" : "ies")
                + (entries == 0 ? optional : ""));
        for (COSName key : vri.keySet()) {
            if (vri.getDictionaryObject(key) instanceof COSDictionary signatureVri) {
                out.add("      " + key.getName() + "  certs=" + arraySize(signatureVri, "Cert")
                        + " ocsp=" + arraySize(signatureVri, "OCSP")
                        + " crl=" + arraySize(signatureVri, "CRL"));
            }
        }
    }

    /**
     * Which certificate each OCSP response answers for - the question a count
     * of responses leaves open. A root needs none, and neither does a responder
     * certificate carrying id-pkix-ocsp-nocheck, so those are named rather than
     * counted as gaps; anything else without a response is called out.
     */
    private static void describeRevocationCoverage(COSDictionary dss, List<String> out) {
        List<X509CertificateHolder> certificates;
        List<BasicOCSPResp> responses = new ArrayList<>();
        try {
            certificates = distinctCertificates(dssStreams(dss, "Certs"));
            for (byte[] encoded : dssStreams(dss, "OCSPs")) {
                try {
                    responses.add((BasicOCSPResp) new OCSPResp(encoded).getResponseObject());
                } catch (Exception e) {
                    out.add("    ! an entry in /OCSPs cannot be read: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            out.add("    ! /DSS cannot be read: " + e.getMessage());
            return;
        }
        if (certificates.isEmpty()) {
            return;
        }
        out.add("    revocation coverage       :");
        for (X509CertificateHolder certificate : certificates) {
            out.add("      " + shortName(certificate) + "  -  " + coverageOf(certificate, certificates, responses));
        }
    }

    private static String coverageOf(X509CertificateHolder certificate,
                                     List<X509CertificateHolder> certificates,
                                     List<BasicOCSPResp> responses) {
        for (BasicOCSPResp response : responses) {
            SingleResp single = entryFor(response, certificate, certificates);
            if (single != null) {
                return statusOf(single) + ", signed by " + responderOf(response);
            }
        }
        if (OcspClient.isSelfSigned(certificate)) {
            return "root, no response needed";
        }
        if (certificate.getExtension(OCSP_NOCHECK) != null) {
            return "OCSP responder (ocsp-nocheck), no response needed";
        }
        return "NO OCSP RESPONSE";
    }

    /**
     * The entry about this certificate, matched the way RFC 6960 requires: the
     * serial together with a hash of the issuer's name and key. When the issuer
     * is not in {@code /Certs} that hash cannot be recomputed, and a serial
     * match is all this report can offer.
     */
    private static SingleResp entryFor(BasicOCSPResp response, X509CertificateHolder certificate,
                                       List<X509CertificateHolder> certificates) {
        for (X509CertificateHolder candidate : certificates) {
            if (!candidate.getSubject().equals(certificate.getIssuer())) {
                continue;
            }
            try {
                SingleResp single = OcspClient.find(response, certificate, candidate);
                if (single != null) {
                    return single;
                }
            } catch (Exception e) {
                // Try the next candidate issuer, then fall back to the serial.
            }
        }
        for (SingleResp single : response.getResponses()) {
            if (single.getCertID().getSerialNumber().equals(certificate.getSerialNumber())) {
                return single;
            }
        }
        return null;
    }

    private static String statusOf(SingleResp single) {
        // BouncyCastle represents 'good' as a null status (CertificateStatus.GOOD).
        Object status = single.getCertStatus();
        if (status == null) {
            return "good";
        }
        if (status instanceof RevokedStatus revoked) {
            return "REVOKED " + revoked.getRevocationTime();
        }
        return "status unknown";
    }

    private static String responderOf(BasicOCSPResp response) {
        X509CertificateHolder[] certificates = response.getCerts();
        return certificates != null && certificates.length > 0
                ? shortName(certificates[0])
                : "a responder the response does not include";
    }

    private static String shortName(X509CertificateHolder certificate) {
        RDN[] cn = certificate.getSubject().getRDNs(BCStyle.CN);
        return cn.length > 0
                ? IETFUtils.valueToString(cn[0].getFirst().getValue())
                : certificate.getSubject().toString();
    }

    private static List<X509CertificateHolder> distinctCertificates(List<byte[]> encoded) throws IOException {
        List<X509CertificateHolder> result = new ArrayList<>();
        for (byte[] bytes : encoded) {
            X509CertificateHolder certificate = new X509CertificateHolder(bytes);
            if (result.stream().noneMatch(known -> known.equals(certificate))) {
                result.add(certificate);
            }
        }
        return result;
    }

    private static List<byte[]> dssStreams(COSDictionary dss, String key) throws IOException {
        List<byte[]> result = new ArrayList<>();
        if (dss.getDictionaryObject(COSName.getPDFName(key)) instanceof COSArray array) {
            for (int i = 0; i < array.size(); i++) {
                if (array.getObject(i) instanceof COSStream stream) {
                    try (InputStream in = stream.createInputStream()) {
                        result.add(in.readAllBytes());
                    }
                }
            }
        }
        return result;
    }

    private static int arraySize(COSDictionary dictionary, String key) {
        COSBase value = dictionary.getDictionaryObject(COSName.getPDFName(key));
        return value instanceof COSArray array ? array.size() : 0;
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
