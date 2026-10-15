package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fills the PDF's Document Security Store ({@code /DSS}) with what a reader
 * needs to validate every signature and timestamp in the document offline:
 * {@code /Certs} holds each certificate chain, {@code /OCSPs} an OCSP response
 * for every certificate below a root, together with the certificates that
 * signed those responses.
 *
 * <p>The chains are taken from the document itself - the signer's CMS, the
 * signature timestamp inside it, and any document timestamp - so the e-seal
 * certificate, its CA, and each TSA are all covered. This is PAdES Part 4
 * (ETSI EN 319 142-1 B-LT): with an {@code ETSI.CAdES.detached} signature,
 * readers look for revocation data here rather than inside the signature.</p>
 *
 * <p>For each certificate a fresh OCSP response is asked of the responder it
 * names, then of the fallbacks. When none answers, a response ADSS already
 * embedded in the signature ({@code adbe-revocationInfoArchival}) is used
 * instead. Every response, fetched or embedded, must be signed by the issuing
 * CA or a responder that CA authorised and report the certificate as good.</p>
 *
 * <p>Every signature gets its own responses, even for a certificate the
 * {@code /DSS} already covers. A response produced before a signature existed
 * says nothing about whether the certificate was still valid when that
 * signature was made, so reusing one would leave each signature after the first
 * without revocation data for its own signing time. {@code /VRI} records which
 * responses belong to which signature; a certificate is still stored once.</p>
 *
 * <p>Written as an incremental update, so no signature or timestamp is touched,
 * and when nothing is new the document is returned unchanged.</p>
 */
public class LongTermValidationData {

    private static final Logger log = LoggerFactory.getLogger(LongTermValidationData.class);
    private static final ASN1ObjectIdentifier ADBE_REVOCATION = new ASN1ObjectIdentifier("1.2.840.113583.1.1.8");
    private static final String TIMESTAMP_SUBFILTER = "ETSI.RFC3161";

    private final OcspClient ocsp;
    private final String configuredOcspUrl;

    public LongTermValidationData(OcspClient ocsp) {
        this(ocsp, null);
    }

    /**
     * @param configuredOcspUrl {@code signing.dss.ocsp.url}; asked first for a
     *                          certificate that names no responder itself
     */
    public LongTermValidationData(OcspClient ocsp, String configuredOcspUrl) {
        this.ocsp = ocsp;
        this.configuredOcspUrl = configuredOcspUrl == null || configuredOcspUrl.isBlank()
                ? null : configuredOcspUrl.trim();
    }

    /** Certificates already asked about during one request, so a second pass does not ask again. */
    public static final class Attempted {
        private final Set<BigInteger> serials = new LinkedHashSet<>();
    }

    /**
     * @return the document with its validation data appended, or the document
     *         unchanged when there is nothing new to add; the signatures are
     *         valid either way, and anything missing is logged
     */
    public byte[] addFor(byte[] pdf, String requestId, Attempted attempted) {
        Material material;
        try {
            material = collect(pdf);
        } catch (Exception e) {
            log.warn("[{}] Cannot read the signatures for their validation data: {}", requestId, e.getMessage());
            return pdf;
        }

        Map<String, byte[]> newCertificates = new LinkedHashMap<>();
        List<byte[]> newResponses = new ArrayList<>();
        List<String> fallbackUrls = fallbackUrls(material.chain);
        // Grows while it is walked: a responder's own chain, carried in its
        // response, needs validation data as well.
        List<X509CertificateHolder> work = new ArrayList<>(material.chain);
        try {
            for (int i = 0; i < work.size(); i++) {
                X509CertificateHolder certificate = work.get(i);
                if (!material.existingCertificates.contains(key(certificate))) {
                    put(newCertificates, certificate);
                }
                // A response already in the /DSS is deliberately not reused. It
                // was produced before this signature existed, so it says nothing
                // about whether the certificate was still valid at this signing
                // time - only a response produced now does. Every signature
                // therefore gets its own, and attempted still stops the same
                // certificate being asked about twice within one request.
                if (OcspClient.isSelfSigned(certificate) || isOcspNoCheck(certificate)
                        || !attempted.serials.add(certificate.getSerialNumber())) {
                    continue;
                }
                Optional<X509CertificateHolder> issuer = issuerOf(certificate, work);
                if (issuer.isEmpty()) {
                    log.warn("[{}] The document does not carry the issuer of {}; its status cannot be checked",
                            requestId, certificate.getSubject());
                    continue;
                }
                Optional<OcspClient.Answer> answer = ocsp.check(certificate, issuer.get(), fallbackUrls);
                if (answer.isEmpty()) {
                    answer = embedded(material.embeddedResponses, certificate, issuer.get());
                }
                if (answer.isPresent()) {
                    newResponses.add(answer.get().encoded());
                    List<X509CertificateHolder> responderChain = new ArrayList<>();
                    responderChain.add(answer.get().responder());
                    responderChain.addAll(answer.get().certificates());
                    for (X509CertificateHolder carried : responderChain) {
                        if (work.stream().noneMatch(carried::equals)) {
                            work.add(carried);
                        }
                    }
                } else {
                    log.warn("[{}] No usable OCSP response for {}; readers will have to check it online",
                            requestId, certificate.getSubject());
                }
            }
        } catch (IOException e) {
            log.warn("[{}] Cannot encode a certificate: {}", requestId, e.getMessage());
            return pdf;
        }

        if (newCertificates.isEmpty() && newResponses.isEmpty()) {
            return pdf;
        }
        try {
            byte[] result = writeDss(pdf, newCertificates.values(), newResponses);
            log.info("[{}] Added validation data to /DSS: {} certificate(s), {} OCSP response(s)",
                    requestId, newCertificates.size(), newResponses.size());
            return result;
        } catch (IOException e) {
            log.warn("[{}] Cannot write the validation data; returning the document without it: {}",
                    requestId, e.getMessage());
            return pdf;
        }
    }

    // ------------------------------------------------------------------
    // What the document holds
    // ------------------------------------------------------------------

    private static final class Material {
        final List<X509CertificateHolder> chain = new ArrayList<>();
        final List<byte[]> embeddedResponses = new ArrayList<>();
        final Set<String> existingCertificates = new LinkedHashSet<>();

        void add(Collection<X509CertificateHolder> certificates) {
            for (X509CertificateHolder certificate : certificates) {
                if (chain.stream().noneMatch(known -> known.equals(certificate))) {
                    chain.add(certificate);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Material collect(byte[] pdf) throws Exception {
        Material material = new Material();
        try (PDDocument document = PDDocument.load(pdf)) {
            for (PDSignature signature : document.getSignatureDictionaries()) {
                byte[] contents = signature.getContents(pdf);
                CMSSignedData cms = new CMSSignedData(contents);
                material.add(cms.getCertificates().getMatches(null));
                if (TIMESTAMP_SUBFILTER.equals(signature.getSubFilter())) {
                    continue;
                }
                for (SignerInformation signer : cms.getSignerInfos().getSigners()) {
                    // The signature timestamp inside the signature has its own TSA chain.
                    AttributeTable unsigned = signer.getUnsignedAttributes();
                    Attribute stamp = unsigned == null ? null
                            : unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                    if (stamp != null) {
                        for (ASN1Encodable value : stamp.getAttrValues()) {
                            TimeStampToken token = new TimeStampToken(new CMSSignedData(
                                    value.toASN1Primitive().getEncoded()));
                            material.add(token.getCertificates().getMatches(null));
                        }
                    }
                    material.embeddedResponses.addAll(adobeRevocation(signer));
                }
            }

            COSBase dss = document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.getPDFName("DSS"));
            if (dss instanceof COSDictionary dictionary) {
                for (byte[] certificate : streams(dictionary, "Certs")) {
                    material.existingCertificates.add(Base64.getEncoder().encodeToString(certificate));
                }
            }
        }
        return material;
    }

    /** OCSP responses ADSS put inside the signature, the Adobe way. */
    private static List<byte[]> adobeRevocation(SignerInformation signer) {
        List<byte[]> responses = new ArrayList<>();
        AttributeTable signed = signer.getSignedAttributes();
        Attribute archival = signed == null ? null : signed.get(ADBE_REVOCATION);
        if (archival == null) {
            return responses;
        }
        try {
            // RevocationInfoArchival ::= SEQUENCE { crl [0], ocsp [1] SEQUENCE OF OCSPResponse, other [2] }
            ASN1Sequence info = ASN1Sequence.getInstance(archival.getAttrValues().getObjectAt(0));
            for (ASN1Encodable element : info) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(element);
                if (tagged.getTagNo() == 1) {
                    for (ASN1Encodable response : ASN1Sequence.getInstance(tagged, true)) {
                        responses.add(OCSPResponse.getInstance(response).getEncoded());
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Cannot read the revocation data embedded in the signature: {}", e.getMessage());
        }
        return responses;
    }

    private Optional<OcspClient.Answer> embedded(List<byte[]> responses, X509CertificateHolder certificate,
                                                 X509CertificateHolder issuer) {
        for (byte[] response : responses) {
            Optional<OcspClient.Answer> answer = ocsp.accept(response, certificate, issuer, "the signature");
            if (answer.isPresent()) {
                log.debug("Using the OCSP response embedded in the signature for {}", certificate.getSubject());
                return answer;
            }
        }
        return Optional.empty();
    }

    private static List<byte[]> streams(COSDictionary dss, String key) throws IOException {
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

    // ------------------------------------------------------------------
    // Chains
    // ------------------------------------------------------------------

    /**
     * Where to ask about a certificate that names no responder: the configured
     * OCSP service first, then the responders the rest of the document names - a
     * PKI usually runs one responder for all of its CAs.
     */
    private List<String> fallbackUrls(Collection<X509CertificateHolder> chain) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        if (configuredOcspUrl != null) {
            urls.add(configuredOcspUrl);
        }
        for (X509CertificateHolder certificate : chain) {
            OcspClient.ocspUrl(certificate).ifPresent(urls::add);
        }
        return List.copyOf(urls);
    }

    /** RFC 6960 id-pkix-ocsp-nocheck: an OCSP responder whose own status is not checked. */
    private static boolean isOcspNoCheck(X509CertificateHolder certificate) {
        return certificate.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")) != null;
    }

    private static Optional<X509CertificateHolder> issuerOf(X509CertificateHolder certificate,
                                                            Collection<X509CertificateHolder> candidates) {
        for (X509CertificateHolder candidate : candidates) {
            if (!candidate.getSubject().equals(certificate.getIssuer())) {
                continue;
            }
            try {
                if (certificate.isSignatureValid(new JcaContentVerifierProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(candidate))) {
                    return Optional.of(candidate);
                }
            } catch (Exception e) {
                // Not this one; keep looking.
            }
        }
        return Optional.empty();
    }

    private static String key(X509CertificateHolder certificate) throws IOException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    /** Keyed by the encoding, so a certificate already listed is not added twice. */
    private static void put(Map<String, byte[]> target, X509CertificateHolder certificate) throws IOException {
        target.putIfAbsent(key(certificate), certificate.getEncoded());
    }

    // ------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------

    private static byte[] writeDss(byte[] pdf, Collection<byte[]> certificates, List<byte[]> responses)
            throws IOException {
        try (PDDocument document = PDDocument.load(pdf)) {
            COSDictionary catalog = document.getDocumentCatalog().getCOSObject();

            COSDictionary dss = asDictionary(catalog.getDictionaryObject(COSName.getPDFName("DSS")));
            if (dss == null) {
                dss = new COSDictionary();
                catalog.setItem(COSName.getPDFName("DSS"), dss);
            }
            COSArray certs = arrayIn(dss, "Certs");
            COSArray ocsps = arrayIn(dss, "OCSPs");
            List<COSStream> addedResponses = new ArrayList<>();
            for (byte[] certificate : certificates) {
                certs.add(stream(document, certificate));
            }
            for (byte[] response : responses) {
                COSStream stream = stream(document, response);
                ocsps.add(stream);
                addedResponses.add(stream);
            }
            // /VRI must exist even when it holds nothing: the ADSS SDK reads it
            // without a null check when /DSS has no /CRLs, and without one the
            // document cannot be signed again.
            COSDictionary vri = asDictionary(dss.getDictionaryObject(COSName.getPDFName("VRI")));
            if (vri == null) {
                vri = new COSDictionary();
                dss.setItem(COSName.getPDFName("VRI"), vri);
            }
            // Every certificate in the /DSS, not only the ones this request
            // added: a certificate is stored once, so later signatures add none
            // and their entries would otherwise list no certificate at all.
            addVriEntries(document, pdf, vri, streamsIn(certs), addedResponses);
            declareExtension(catalog);

            // An incremental save writes only what is marked as changed.
            catalog.setNeedToBeUpdated(true);
            dss.setNeedToBeUpdated(true);
            certs.setNeedToBeUpdated(true);
            ocsps.setNeedToBeUpdated(true);
            vri.setNeedToBeUpdated(true);

            ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + 32_768);
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    /**
     * Gives each signature a {@code /VRI} entry of its own, holding the material
     * this request fetched, keyed by the uppercase base-16 SHA-1 of the
     * signature's {@code /Contents} as ISO 32000-2 12.8.4.3 requires.
     *
     * <p>Without it every response lies in one flat {@code /OCSPs} pool and
     * nothing says which signature a response belongs to - the distinction that
     * matters once a document is signed several times, because each signature
     * needs the response produced at <em>its</em> signing time. A signature that
     * already has an entry keeps it: that material was collected when it was
     * made, and this request's responses postdate it.</p>
     *
     * <p>The {@code /Cert} array lists every certificate the {@code /DSS} holds,
     * which for a document signed by one seal is its chain and the TSAs' - a
     * superset a reader selects from, rather than the empty array a later
     * signature would get from a certificate store that keeps each one once.</p>
     */
    private static void addVriEntries(PDDocument document, byte[] pdf, COSDictionary vri,
                                      List<COSStream> certificates, List<COSStream> responses)
            throws IOException {
        if (certificates.isEmpty() && responses.isEmpty()) {
            return;
        }
        Calendar now = Calendar.getInstance();
        for (PDSignature signature : document.getSignatureDictionaries()) {
            String key;
            try {
                key = vriKey(signature.getContents(pdf));
            } catch (Exception e) {
                // A signature whose /Contents cannot be read cannot be keyed;
                // its material is still in /Certs and /OCSPs.
                continue;
            }
            if (vri.getDictionaryObject(COSName.getPDFName(key)) != null) {
                continue;
            }
            COSDictionary entry = new COSDictionary();
            if (!certificates.isEmpty()) {
                entry.setItem(COSName.getPDFName("Cert"), arrayOf(certificates));
            }
            if (!responses.isEmpty()) {
                entry.setItem(COSName.getPDFName("OCSP"), arrayOf(responses));
            }
            entry.setDate(COSName.getPDFName("TU"), now);
            entry.setNeedToBeUpdated(true);
            vri.setItem(COSName.getPDFName(key), entry);
        }
    }

    /** ISO 32000-2 12.8.4.3: the uppercase base-16 SHA-1 of the /Contents value. */
    private static String vriKey(byte[] contents) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(contents);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    private static List<COSStream> streamsIn(COSArray array) {
        List<COSStream> streams = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            if (array.getObject(i) instanceof COSStream stream) {
                streams.add(stream);
            }
        }
        return streams;
    }

    /** The streams are shared with /Certs and /OCSPs, not written again. */
    private static COSArray arrayOf(List<COSStream> streams) {
        COSArray array = new COSArray();
        streams.forEach(array::add);
        array.setNeedToBeUpdated(true);
        return array;
    }

    private static COSArray arrayIn(COSDictionary dss, String key) {
        COSBase existing = dss.getDictionaryObject(COSName.getPDFName(key));
        if (existing instanceof COSArray array) {
            return array;
        }
        COSArray array = new COSArray();
        dss.setItem(COSName.getPDFName(key), array);
        return array;
    }

    private static COSDictionary asDictionary(COSBase base) {
        return base instanceof COSDictionary dictionary ? dictionary : null;
    }

    private static COSStream stream(PDDocument document, byte[] data) throws IOException {
        COSStream stream = document.getDocument().createCOSStream();
        try (OutputStream out = stream.createOutputStream(COSName.FLATE_DECODE)) {
            out.write(data);
        }
        stream.setNeedToBeUpdated(true);
        return stream;
    }

    /** ISO 32000-1 extension level 5 is what introduced /DSS; readers look for it. */
    private static void declareExtension(COSDictionary catalog) {
        COSDictionary extensions = asDictionary(catalog.getDictionaryObject(COSName.getPDFName("Extensions")));
        if (extensions == null) {
            extensions = new COSDictionary();
            catalog.setItem(COSName.getPDFName("Extensions"), extensions);
        }
        if (extensions.getDictionaryObject(COSName.getPDFName("ESIC")) == null) {
            COSDictionary esic = new COSDictionary();
            esic.setName(COSName.getPDFName("BaseVersion"), "1.7");
            esic.setInt(COSName.getPDFName("ExtensionLevel"), 5);
            extensions.setItem(COSName.getPDFName("ESIC"), esic);
        }
        extensions.setNeedToBeUpdated(true);
    }
}
