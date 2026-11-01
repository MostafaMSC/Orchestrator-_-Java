package iq.twokeyok.orchestrator.signing.gosign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * Signing a PDF in two halves, because the key is on the signer's token and
 * the signing happens between two HTTP requests.
 *
 * <p>{@link #prepare} writes the signature dictionary with its
 * {@code /Contents} left as zeros, fixes the {@code /ByteRange} around that gap
 * and returns the digest of everything the ranges cover.
 * {@link #inject} puts the CMS the token produced into that gap. Because
 * {@code /Contents} is excluded from the ranges by construction, filling it
 * changes nothing the digest covered - which is what makes the two halves
 * separable at all.</p>
 *
 * <p>PDFBox's {@code saveIncrementalForExternalSigning} does both halves in one
 * open document, which a single request cannot span: the signer has to open a
 * page and enter a PIN in between. So the prepared bytes are kept and the gap is
 * refilled later by offset, the digest being re-derived from the stored document
 * each time rather than trusted.</p>
 */
public final class DeferredPdfSignature {

    private static final Map<String, String> DIGESTS = Map.of(
            "SHA1", "SHA-1", "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "SHA-512");

    private DeferredPdfSignature() {
    }

    /**
     * A document waiting for its signature.
     *
     * @param pdf          the document with the signature dictionary in place and
     *                     {@code /Contents} zero-filled
     * @param digest       the digest of what {@code /ByteRange} covers - what the
     *                     token is asked to sign
     * @param fieldName    the signature field the signature belongs to
     * @param digestName   JCA name of the algorithm the digest was taken with
     */
    public record Prepared(byte[] pdf, byte[] digest, String fieldName, String digestName) {
    }

    /**
     * @param pdf            the document to sign
     * @param fieldName      signature field to sign into; created when absent
     * @param hashAlgorithm  {@code SHA256} and the like, as Go>Sign names them
     * @param signatureSize  bytes reserved for the CMS in {@code /Contents}
     */
    public static Prepared prepare(byte[] pdf, String fieldName, String subFilter, String hashAlgorithm,
                                   int signatureSize, SignatureMetadata metadata) {
        String digestName = digestName(hashAlgorithm);
        try (PDDocument document = PDDocument.load(pdf)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(COSName.getPDFName(subFilter));
            signature.setSignDate(Calendar.getInstance());
            if (metadata != null) {
                metadata.applyTo(signature);
            }

            // Sign into the field the caller named when the document already has
            // one, so a second signer does not create a duplicate.
            PDSignatureField existing = fieldNamed(document, fieldName);
            if (existing != null) {
                existing.getCOSObject().setItem(COSName.V, signature.getCOSObject());
            }

            SignatureOptions options = new SignatureOptions();
            // The CMS from a token carries its certificate chain, so the default
            // reservation is not always enough; running out cannot be fixed after
            // the ranges are written.
            options.setPreferredSignatureSize(Math.max(SignatureOptions.DEFAULT_SIGNATURE_SIZE, signatureSize));
            document.addSignature(signature, options);

            ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + signatureSize + 4096);
            org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport external =
                    document.saveIncrementalForExternalSigning(out);
            byte[] covered;
            try (InputStream in = external.getContent()) {
                covered = in.readAllBytes();
            }
            byte[] digest = MessageDigest.getInstance(digestName).digest(covered);
            // Nothing to put in the gap yet; an empty array leaves it as the
            // zeros already written, which is exactly the placeholder wanted.
            external.setSignature(new byte[0]);

            byte[] prepared = out.toByteArray();
            // The gap must be re-findable from the stored bytes alone, since the
            // open document does not survive the wait for the token.
            verifyDigest(prepared, digest, digestName);
            return new Prepared(prepared, digest, fieldName, digestName);
        } catch (OrchestratorException e) {
            throw e;
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                    "the document could not be prepared for signing: " + e.getMessage());
        }
    }

    /**
     * Puts {@code cms} into the prepared document's {@code /Contents}.
     *
     * <p>Refuses rather than returns a broken document: the digest is taken from
     * the prepared bytes again and must match what {@link #prepare} recorded, the
     * CMS must fit the reserved gap, and the signature must verify over those
     * same bytes before anything is handed back.</p>
     */
    public static byte[] inject(Prepared prepared, byte[] cms) {
        if (cms == null || cms.length == 0) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID, "no signature was returned");
        }
        verifyDigest(prepared.pdf(), prepared.digest(), prepared.digestName());

        int[] range = byteRange(prepared.pdf());
        int gapStart = range[0] + range[1];
        int gapEnd = range[2];
        int capacity = gapEnd - gapStart - 2;
        String hex = hex(cms);
        if (hex.length() > capacity) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                    "the signature needs " + (hex.length() / 2) + " bytes but only "
                            + (capacity / 2) + " are reserved; raise signing.gosign.signature_size");
        }

        byte[] signed = prepared.pdf().clone();
        if (signed[gapStart] != '<' || signed[gapEnd - 1] != '>') {
            throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                    "the signature placeholder is not where /ByteRange says it is");
        }
        for (int i = 0; i < capacity; i++) {
            signed[gapStart + 1 + i] = (byte) (i < hex.length() ? hex.charAt(i) : '0');
        }

        verifySignature(signed, cms, prepared);
        return signed;
    }

    /** The content the signature covers: everything outside {@code /Contents}. */
    static byte[] covered(byte[] pdf) {
        int[] range = byteRange(pdf);
        byte[] covered = new byte[range[1] + range[3]];
        System.arraycopy(pdf, range[0], covered, 0, range[1]);
        System.arraycopy(pdf, range[2], covered, range[1], range[3]);
        return covered;
    }

    private static void verifyDigest(byte[] pdf, byte[] expected, String digestName) {
        try {
            byte[] actual = MessageDigest.getInstance(digestName).digest(covered(pdf));
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                        "the digest of the prepared document no longer matches the one registered");
            }
        } catch (OrchestratorException e) {
            throw e;
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                    "the prepared document cannot be digested: " + e.getMessage());
        }
    }

    /**
     * The signature must verify over the bytes it was injected into, against the
     * certificate it carries. A token that signed a different digest, or a
     * response that was never a signature at all, fails here rather than being
     * returned as a signed document.
     */
    private static void verifySignature(byte[] signed, byte[] cms, Prepared prepared) {
        try {
            CMSSignedData data = new CMSSignedData(new CMSProcessableByteArray(covered(signed)), cms);
            @SuppressWarnings("unchecked")
            List<X509CertificateHolder> certificates =
                    List.copyOf(data.getCertificates().getMatches(null));
            boolean verified = false;
            for (SignerInformation signer : data.getSignerInfos().getSigners()) {
                for (X509CertificateHolder holder : certificates) {
                    if (!signer.getSID().match(holder)) {
                        continue;
                    }
                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                            .build(new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder)))) {
                        verified = true;
                    }
                }
            }
            if (!verified) {
                throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                        "no signer in the CMS verifies over the document");
            }
        } catch (OrchestratorException e) {
            throw e;
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID,
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /** The {@code /ByteRange} of the last signature dictionary in the document. */
    private static int[] byteRange(byte[] pdf) {
        try (PDDocument document = PDDocument.load(pdf)) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                        "the prepared document carries no signature dictionary");
            }
            int[] range = signatures.get(signatures.size() - 1).getByteRange();
            if (range == null || range.length != 4) {
                throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                        "the signature has no usable /ByteRange");
            }
            return range;
        } catch (OrchestratorException e) {
            throw e;
        } catch (IOException e) {
            throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                    "the prepared document cannot be read: " + e.getMessage());
        }
    }

    private static PDSignatureField fieldNamed(PDDocument document, String name) {
        PDAcroForm form = document.getDocumentCatalog().getAcroForm();
        if (form == null || name == null) {
            return null;
        }
        for (PDField field : form.getFieldTree()) {
            if (field instanceof PDSignatureField signatureField
                    && name.equals(field.getFullyQualifiedName())) {
                return signatureField;
            }
        }
        return null;
    }

    static String digestName(String hashAlgorithm) {
        String key = hashAlgorithm == null ? "SHA256"
                : hashAlgorithm.toUpperCase(Locale.ROOT).replace("-", "").trim();
        String name = DIGESTS.get(key);
        if (name == null) {
            throw new OrchestratorException(ErrorCode.UNSUPPORTED_HASH_ALGORITHM, hashAlgorithm);
        }
        return name;
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    /** Signature dictionary fields a signer configuration supplies. */
    public record SignatureMetadata(String name, String reason, String location, String contactInfo) {

        void applyTo(PDSignature signature) {
            if (name != null && !name.isBlank()) {
                signature.setName(name);
            }
            if (reason != null && !reason.isBlank()) {
                signature.setReason(reason);
            }
            if (location != null && !location.isBlank()) {
                signature.setLocation(location);
            }
            if (contactInfo != null && !contactInfo.isBlank()) {
                signature.setContactInfo(contactInfo);
            }
        }
    }
}
