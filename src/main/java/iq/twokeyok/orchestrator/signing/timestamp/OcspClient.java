package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asks the OCSP responder named in a certificate's Authority Information Access
 * extension whether that certificate is still good, and returns the response
 * only when it can be trusted to say so.
 *
 * <p>A response is accepted when it is successful, is signed either by the
 * issuing CA or by a responder certificate that CA issued for OCSP signing,
 * refers to exactly the certificate asked about, and reports it as good.
 * Anything else is reported as absent, never embedded.</p>
 */
public class OcspClient {

    private static final Logger log = LoggerFactory.getLogger(OcspClient.class);

    /**
     * A trusted, good OCSP answer, the certificate that signed it, and the other
     * certificates the response carried (the responder's chain).
     */
    public record Answer(byte[] encoded, X509CertificateHolder responder, List<X509CertificateHolder> certificates) {
    }

    private final HttpClient http;
    private final Duration timeout;
    /** SHA-256 fingerprints, upper-case hex without separators. */
    private final java.util.Set<String> pinnedResponders;

    public OcspClient(int timeoutMs) {
        this(timeoutMs, List.of());
    }

    /**
     * @param pinnedResponders SHA-256 fingerprints of responder certificates
     *                         accepted outside RFC 6960's issuer rule
     *                         ({@code signing.dss.ocsp.trusted_responders})
     */
    public OcspClient(int timeoutMs, java.util.Collection<String> pinnedResponders) {
        this.pinnedResponders = new java.util.HashSet<>();
        for (String fingerprint : pinnedResponders) {
            if (fingerprint != null && !fingerprint.isBlank()) {
                this.pinnedResponders.add(normaliseFingerprint(fingerprint));
            }
        }
        this.timeout = Duration.ofMillis(Math.max(1000, timeoutMs));
        // HTTP/1.1 only. On a plain http:// URL the JDK client otherwise asks to
        // upgrade to HTTP/2 (h2c), and the staging responder answers that by
        // closing the connection: "HTTP/1.1 header parser received no bytes".
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(timeout)
                .build();
    }

    /** @return the OCSP URL in the certificate, if it names one */
    public static Optional<String> ocspUrl(X509CertificateHolder certificate) {
        AuthorityInformationAccess aia = AuthorityInformationAccess.fromExtensions(certificate.getExtensions());
        if (aia == null) {
            return Optional.empty();
        }
        for (AccessDescription description : aia.getAccessDescriptions()) {
            if (AccessDescription.id_ad_ocsp.equals(description.getAccessMethod())
                    && description.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                return Optional.of(description.getAccessLocation().getName().toString());
            }
        }
        return Optional.empty();
    }

    /**
     * @param fallbackUrls responders to ask, in order, when the certificate names
     *                     none itself - a CA certificate often carries no
     *                     Authority Information Access although a responder for
     *                     it exists
     * @return the response, when a responder vouches that {@code certificate}
     *         is good; empty when there is no responder or no usable answer
     */
    public Optional<Answer> check(X509CertificateHolder certificate, X509CertificateHolder issuer,
                                  List<String> fallbackUrls) {
        Optional<String> named = ocspUrl(certificate);
        if (named.isPresent()) {
            return check(certificate, issuer, named.get());
        }
        for (String url : fallbackUrls) {
            Optional<Answer> answer = check(certificate, issuer, url);
            if (answer.isPresent()) {
                log.debug("{} names no OCSP responder; {} answered for it", certificate.getSubject(), url);
                return answer;
            }
        }
        log.debug("No OCSP responder answered for {}", certificate.getSubject());
        return Optional.empty();
    }

    public Optional<Answer> check(X509CertificateHolder certificate, X509CertificateHolder issuer) {
        return check(certificate, issuer, List.of());
    }

    private Optional<Answer> check(X509CertificateHolder certificate, X509CertificateHolder issuer, String url) {
        try {
            CertificateID id = new CertificateID(
                    new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    issuer, certificate.getSerialNumber());
            byte[] request = new OCSPReqBuilder().addRequest(id).build().getEncoded();

            HttpResponse<byte[]> reply = http.send(HttpRequest.newBuilder(URI.create(url))
                            .timeout(timeout)
                            .header("Content-Type", "application/ocsp-request")
                            .header("Accept", "application/ocsp-response")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(request))
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            if (reply.statusCode() != 200) {
                log.warn("OCSP responder {} answered HTTP {} for {}", url, reply.statusCode(),
                        certificate.getSubject());
                return Optional.empty();
            }

            return accept(reply.body(), certificate, issuer, url);
        } catch (IOException e) {
            log.warn("OCSP responder {} is not reachable for {}: {}", url, certificate.getSubject(),
                    e.getMessage());
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            log.warn("OCSP response from {} for {} cannot be used: {}", url, certificate.getSubject(),
                    e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Applies the same checks to a response obtained elsewhere - for example
     * one ADSS already embedded in the signature - as to one fetched here.
     *
     * @param source where it came from, for the log
     */
    public Optional<Answer> accept(byte[] encoded, X509CertificateHolder certificate, X509CertificateHolder issuer,
                                   String source) {
        try {
            OCSPResp response = new OCSPResp(encoded);
            if (response.getStatus() != OCSPResp.SUCCESSFUL) {
                log.warn("OCSP response from {} for {} is not successful (status {})", source,
                        certificate.getSubject(), response.getStatus());
                return Optional.empty();
            }
            BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
            SingleResp single = find(basic, certificate, issuer);
            if (single == null) {
                log.debug("OCSP response from {} does not cover {}", source, certificate.getSubject());
                return Optional.empty();
            }
            X509CertificateHolder responder = trustedResponder(basic, issuer);
            if (responder == null) {
                log.warn("OCSP response for {} from {} is not signed by its CA or a responder that CA authorised",
                        certificate.getSubject(), source);
                return Optional.empty();
            }
            if (single.getCertStatus() != CertificateStatus.GOOD) {
                log.warn("OCSP reports {} as not good; no validation data is added for it",
                        certificate.getSubject());
                return Optional.empty();
            }
            List<X509CertificateHolder> carried = new java.util.ArrayList<>();
            for (X509CertificateHolder included : basic.getCerts()) {
                if (!included.equals(responder)) {
                    carried.add(included);
                }
            }
            return Optional.of(new Answer(response.getEncoded(), responder, carried));
        } catch (Exception e) {
            log.warn("OCSP response from {} for {} cannot be used: {}", source, certificate.getSubject(),
                    e.getMessage());
            return Optional.empty();
        }
    }

    /** The entry about {@code certificate}, if the response has one. */
    public static SingleResp find(BasicOCSPResp basic, X509CertificateHolder certificate,
                                  X509CertificateHolder issuer) throws Exception {
        for (SingleResp single : basic.getResponses()) {
            if (single.getCertID().getSerialNumber().equals(certificate.getSerialNumber())
                    && single.getCertID().matchesIssuer(issuer, new JcaDigestCalculatorProviderBuilder().build())) {
                return single;
            }
        }
        return null;
    }

    /** The certificate that signed the response, if it is one that may. */
    private X509CertificateHolder trustedResponder(BasicOCSPResp basic, X509CertificateHolder issuer)
            throws Exception {
        X509CertificateHolder authorised = authorisedResponder(basic, issuer);
        if (authorised != null || pinnedResponders.isEmpty()) {
            return authorised;
        }
        // A responder pinned by fingerprint, accepted although another CA issued
        // it. It must still be a current OCSP-signing certificate that signed
        // this response; only the issuer rule is waived, and only for it.
        for (X509CertificateHolder candidate : basic.getCerts()) {
            ExtendedKeyUsage usage = ExtendedKeyUsage.fromExtensions(candidate.getExtensions());
            if (pinnedResponders.contains(fingerprint(candidate))
                    && usage != null && usage.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning)
                    && candidate.isValidOn(new java.util.Date())
                    && signedBy(basic, candidate)) {
                log.info("Accepting OCSP responder {} by its pinned fingerprint "
                        + "(signing.dss.ocsp.trusted_responders), although {} did not issue it",
                        candidate.getSubject(), issuer.getSubject());
                return candidate;
            }
        }
        return null;
    }

    public static String fingerprint(X509CertificateHolder certificate) throws java.io.IOException {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            return java.util.HexFormat.of().withUpperCase().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String normaliseFingerprint(String fingerprint) {
        return fingerprint.trim().replace(":", "").replace(" ", "").toUpperCase(java.util.Locale.ROOT);
    }

    /** RFC 6960: the CA itself, or a responder that CA issued for OCSP signing. */
    private static X509CertificateHolder authorisedResponder(BasicOCSPResp basic, X509CertificateHolder issuer) {
        // Signed by the CA itself.
        if (signedBy(basic, issuer)) {
            return issuer;
        }
        // Signed by a delegated responder: issued by that CA, for OCSP signing.
        for (X509CertificateHolder candidate : basic.getCerts()) {
            boolean issuedByCa = candidate.getIssuer().equals(issuer.getSubject()) && issuedBy(candidate, issuer);
            ExtendedKeyUsage usage = ExtendedKeyUsage.fromExtensions(candidate.getExtensions());
            boolean forOcsp = usage != null && usage.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
            if (issuedByCa && forOcsp && candidate.isValidOn(new java.util.Date()) && signedBy(basic, candidate)) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Whether {@code certificate}'s key signed the response. A key that cannot
     * verify this signature at all - an EC key against an RSA signature, say -
     * makes the provider throw rather than answer; that means "not this one",
     * and the next candidate must still be tried.
     */
    private static boolean signedBy(BasicOCSPResp basic, X509CertificateHolder certificate) {
        try {
            return basic.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(certificate));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean issuedBy(X509CertificateHolder certificate, X509CertificateHolder issuer) {
        try {
            return certificate.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuer));
        } catch (Exception e) {
            return false;
        }
    }

    /** Whether a certificate is a self-signed root, which has no revocation to check. */
    public static boolean isSelfSigned(X509CertificateHolder certificate) {
        return certificate.getSubject().equals(certificate.getIssuer());
    }
}
