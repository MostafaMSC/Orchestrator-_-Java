package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adds the validation data for a document timestamp to the PDF's Document
 * Security Store ({@code /DSS}): the TSA's certificate chain, an OCSP response
 * for every certificate in it below the root, and the certificates that signed
 * those responses.
 *
 * <p>With that data inside the file, a reader can confirm the TSA certificate
 * was not revoked without going online. Without it, Acrobat reports the
 * timestamp's validity as unknown whenever it cannot reach the responder
 * itself, which is the usual case for a staging PKI.</p>
 *
 * <p>Written as one more incremental update, so neither the signature nor the
 * timestamp is touched. An existing {@code /DSS} is extended, not replaced.</p>
 */
public class TimestampValidationData {

    private static final Logger log = LoggerFactory.getLogger(TimestampValidationData.class);

    private final OcspClient ocsp;

    public TimestampValidationData(OcspClient ocsp) {
        this.ocsp = ocsp;
    }

    /**
     * @return the document with the validation data appended, or the document
     *         unchanged when no OCSP response could be obtained; the timestamp is
     *         valid either way, and the reason is logged
     */
    public byte[] addFor(byte[] pdf, TimeStampToken token, String requestId) {
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> chain = token.getCertificates().getMatches(null);

        Map<String, byte[]> certificates = new LinkedHashMap<>();
        List<byte[]> responses = new ArrayList<>();
        try {
            for (X509CertificateHolder certificate : chain) {
                put(certificates, certificate);
                if (OcspClient.isSelfSigned(certificate)) {
                    continue;
                }
                Optional<X509CertificateHolder> issuer = issuerOf(certificate, chain);
                if (issuer.isEmpty()) {
                    log.warn("[{}] The timestamp does not carry the issuer of {}; its status cannot be checked",
                            requestId, certificate.getSubject());
                    continue;
                }
                Optional<OcspClient.Answer> answer = ocsp.check(certificate, issuer.get());
                if (answer.isPresent()) {
                    responses.add(answer.get().encoded());
                    put(certificates, answer.get().responder());
                }
            }
        } catch (IOException e) {
            log.warn("[{}] Cannot encode a TSA certificate: {}", requestId, e.getMessage());
            return pdf;
        }

        if (responses.isEmpty()) {
            log.warn("[{}] No OCSP response for the TSA certificate could be obtained; the document "
                    + "timestamp is valid, but readers will have to check its revocation online", requestId);
            return pdf;
        }

        try {
            byte[] result = writeDss(pdf, certificates.values(), responses);
            log.info("[{}] Added validation data for the document timestamp: {} certificate(s), {} OCSP response(s)",
                    requestId, certificates.size(), responses.size());
            return result;
        } catch (IOException e) {
            log.warn("[{}] Cannot write the validation data; returning the timestamped document without it: {}",
                    requestId, e.getMessage());
            return pdf;
        }
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

    /** Keyed by the encoding, so a certificate already listed is not added twice. */
    private static void put(Map<String, byte[]> target, X509CertificateHolder certificate) throws IOException {
        byte[] encoded = certificate.getEncoded();
        target.putIfAbsent(java.util.Base64.getEncoder().encodeToString(encoded), encoded);
    }

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
