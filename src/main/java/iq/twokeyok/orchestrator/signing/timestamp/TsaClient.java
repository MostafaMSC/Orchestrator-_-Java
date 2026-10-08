package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * An RFC 3161 client: posts a {@code application/timestamp-query} carrying a
 * digest and returns the granted token.
 *
 * <p>Nothing but the digest leaves this process. The reply is checked before it
 * is used — status granted, the imprint is ours, the nonce is ours, and the
 * policy is the one asked for — so a token for some other request can never be
 * embedded in a document.</p>
 *
 * <p>TLS trusts the JVM's default authorities and, when configured,
 * {@code signing.truststore_path}, the same truststore used for ADSS.</p>
 */
public class TsaClient {

    private static final Logger log = LoggerFactory.getLogger(TsaClient.class);

    private static final Map<String, ASN1ObjectIdentifier> DIGESTS = Map.of(
            "SHA1", OIWObjectIdentifiers.idSHA1,
            "SHA256", NISTObjectIdentifiers.id_sha256,
            "SHA384", NISTObjectIdentifiers.id_sha384,
            "SHA512", NISTObjectIdentifiers.id_sha512);

    private final URI url;
    private final String policyId;
    private final String hashAlgorithm;
    private final Duration timeout;
    private final HttpClient http;
    private final SecureRandom random = new SecureRandom();

    public TsaClient(String url, String policyId, String hashAlgorithm, int timeoutMs,
                     String truststorePath, String truststorePassword) {
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("signing.dss.tsa.document-timestamp is on but signing.dss.tsa.url is not set");
        }
        this.url = URI.create(url.trim());
        this.policyId = policyId == null || policyId.isBlank() ? null : policyId.trim();
        this.hashAlgorithm = normalise(hashAlgorithm);
        if (!DIGESTS.containsKey(this.hashAlgorithm)) {
            throw new IllegalStateException("signing.dss.tsa.hash_algorithm must be one of " + DIGESTS.keySet()
                    + ", not " + hashAlgorithm);
        }
        this.timeout = Duration.ofMillis(Math.max(1000, timeoutMs));
        // HTTP/1.1 only, as for OCSP: an h2c upgrade offer on a plain http://
        // TSA URL gets the connection dropped by servers that do not speak it.
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(this.timeout)
                .sslContext(sslContext(truststorePath, truststorePassword))
                .build();
    }

    /** The JCA name of the digest the TSA is asked to timestamp, e.g. {@code SHA-256}. */
    public String digestAlgorithm() {
        return switch (hashAlgorithm) {
            case "SHA1" -> "SHA-1";
            default -> "SHA-" + hashAlgorithm.substring(3);
        };
    }

    public URI url() {
        return url;
    }

    /**
     * @param digest the digest of the data to timestamp, computed with
     *               {@link #digestAlgorithm()}
     * @return the granted token, already checked against the request
     */
    public TimeStampToken timestamp(byte[] digest) {
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        // The TSA certificate goes into the token, so verifiers need nothing else.
        generator.setCertReq(true);
        if (policyId != null) {
            generator.setReqPolicy(new ASN1ObjectIdentifier(policyId));
        }
        BigInteger nonce = new BigInteger(64, random);
        TimeStampRequest request = generator.generate(DIGESTS.get(hashAlgorithm), digest, nonce);

        byte[] reply = post(request);
        try {
            TimeStampResponse response = new TimeStampResponse(reply);
            // Checks the status, and that imprint, nonce and policy are the ones requested.
            response.validate(request);
            TimeStampToken token = response.getTimeStampToken();
            if (token == null) {
                throw new OrchestratorException(ErrorCode.TSA_REJECTED,
                        "status " + response.getStatus() + " " + nullSafe(response.getStatusString()));
            }
            log.debug("TSA {} granted serial {} at {}", url, token.getTimeStampInfo().getSerialNumber(),
                    token.getTimeStampInfo().getGenTime());
            return token;
        } catch (TSPException | IOException e) {
            throw new OrchestratorException(ErrorCode.TSA_REJECTED, e, e.getMessage());
        }
    }

    private byte[] post(TimeStampRequest request) {
        try {
            HttpRequest httpRequest = HttpRequest.newBuilder(url)
                    .timeout(timeout)
                    .header("Content-Type", "application/timestamp-query")
                    .header("Accept", "application/timestamp-reply")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(request.getEncoded()))
                    .build();
            HttpResponse<byte[]> response = http.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                throw new OrchestratorException(ErrorCode.TSA_REJECTED, "HTTP " + response.statusCode());
            }
            return response.body();
        } catch (IOException e) {
            throw new OrchestratorException(ErrorCode.TSA_UNAVAILABLE, e, url + " - " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OrchestratorException(ErrorCode.TSA_UNAVAILABLE, e, url + " - interrupted");
        }
    }

    private static String normalise(String algorithm) {
        return algorithm == null ? "SHA256"
                : algorithm.trim().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    // ------------------------------------------------------------------
    // TLS
    // ------------------------------------------------------------------

    private static SSLContext sslContext(String truststorePath, String truststorePassword) {
        try {
            X509TrustManager defaults = trustManager(null);
            X509TrustManager configured = truststorePath == null || truststorePath.isBlank()
                    ? null : trustManager(load(truststorePath, truststorePassword));
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {configured == null ? defaults : either(configured, defaults)},
                    null);
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot set up TLS for the timestamp authority: " + e.getMessage(), e);
        }
    }

    private static KeyStore load(String path, String password) throws Exception {
        char[] secret = password == null ? null : password.toCharArray();
        Exception last = null;
        for (String type : new String[] {"PKCS12", "JKS"}) {
            try (InputStream in = Files.newInputStream(Path.of(path))) {
                KeyStore store = KeyStore.getInstance(type);
                store.load(in, secret);
                return store;
            } catch (Exception e) {
                last = e;
            }
        }
        throw last;
    }

    private static X509TrustManager trustManager(KeyStore store) throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException("no X509TrustManager available");
    }

    /** Accepts a server either the configured truststore or the JVM defaults trust. */
    private static X509TrustManager either(X509TrustManager first, X509TrustManager second) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                try {
                    first.checkClientTrusted(chain, authType);
                } catch (CertificateException e) {
                    second.checkClientTrusted(chain, authType);
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                try {
                    first.checkServerTrusted(chain, authType);
                } catch (CertificateException e) {
                    second.checkServerTrusted(chain, authType);
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                X509Certificate[] a = first.getAcceptedIssuers();
                X509Certificate[] b = second.getAcceptedIssuers();
                X509Certificate[] all = new X509Certificate[a.length + b.length];
                System.arraycopy(a, 0, all, 0, a.length);
                System.arraycopy(b, 0, all, a.length, b.length);
                return all;
            }
        };
    }
}
