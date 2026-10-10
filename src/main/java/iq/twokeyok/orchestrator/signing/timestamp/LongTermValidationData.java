package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
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
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
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
 * <p>Written as an incremental update, so no signature or timestamp is
 * touched. What the {@code /DSS} already covers is not added again, and when
 * nothing is new the document is returned unchanged.</p>
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
        try {
            for (X509CertificateHolder certificate : material.chain) {
                if (!material.existingCertificates.contains(key(certificate))) {
                    put(newCertificates, certificate);
                }
                if (OcspClient.isSelfSigned(certificate) || material.covered(certificate)
                        || !attempted.serials.add(certificate.getSerialNumber())) {
                    continue;
                }
                Optional<X509CertificateHolder> issuer = issuerOf(certificate, material.chain);
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
                    if (!material.existingCertificates.contains(key(answer.get().responder()))) {
                        put(newCertificates, answer.get().responder());
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
        final List<BasicOCSPResp> existingResponses = new ArrayList<>();

        void add(Collection<X509CertificateHolder> certificates) {
            for (X509CertificateHolder certificate : certificates) {
                if (chain.stream().noneMatch(known -> known.equals(certificate))) {
                    chain.add(certificate);
                }
            }
        }

        /** Whether the /DSS already holds an OCSP response about this certificate. */
        boolean covered(X509CertificateHolder certificate) {
            for (BasicOCSPResp response : existingResponses) {
                for (SingleResp single : response.getResponses()) {
                    if (single.getCertID().getSerialNumber().equals(certificate.getSerialNumber())) {
                        return true;
                    }
                }
            }
            return false;
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
                for (byte[] response : streams(dictionary, "OCSPs")) {
                    try {
                        material.existingResponses.add((BasicOCSPResp) new OCSPResp(response).getResponseObject());
                    } catch (Exception e) {
                        // An unreadable entry is simply not counted as coverage.
                    }
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
            for (byte[] certificate : certificates) {
                certs.add(stream(document, certificate));
            }
            for (byte[] response : responses) {
                ocsps.add(stream(document, response));
            }
            declareExtension(catalog);

            // An incremental save writes only what is marked as changed.
            catalog.setNeedToBeUpdated(true);
            dss.setNeedToBeUpdated(true);
            certs.setNeedToBeUpdated(true);
            ocsps.setNeedToBeUpdated(true);

            ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + 32_768);
            document.saveIncremental(out);
            return out.toByteArray();
        }
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
