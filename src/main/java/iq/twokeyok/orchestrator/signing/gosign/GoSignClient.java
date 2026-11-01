package iq.twokeyok.orchestrator.signing.gosign;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * The ADSS Go>Sign Service HTTP protocol, as the service actually behaves.
 *
 * <p>Three calls matter here. {@link #openSession} posts a document and gets
 * back the HTML snippet the signer's browser runs, carrying a document id.
 * {@link #registerHash} posts {@code REQUEST_TYPE: SET_HASH} against that id
 * with a digest, which is what the token ends up signing. {@link #download}
 * collects the result once the token has signed.</p>
 *
 * <p>Two behaviours were established against the staging service rather than
 * read from the guide, because the guide does not state them:</p>
 * <ul>
 *   <li>{@code SET_HASH} cannot open a transaction. Sent with an id the service
 *       does not know it answers {@code HTTP 500} with no status header, so a
 *       session must be opened with a document first.</li>
 *   <li>The digest need not be the digest of that document. A session opened
 *       with a stub and given an unrelated hash answers {@code SUCCESS}, which
 *       is what lets the document being signed stay on this host.</li>
 * </ul>
 */
public class GoSignClient {

    private static final Logger log = LoggerFactory.getLogger(GoSignClient.class);

    private static final Pattern DOCUMENT_ID = Pattern.compile("GoSign_SetDocumentID\\('([^']+)'\\)");
    private static final Pattern FIELD_NAME = Pattern.compile("GoSign_SetEmptySignatureFieldName\\('([^']+)'\\)");
    private static final String STATUS = "GOSIGN_RESPONSE_STATUS";
    private static final String MESSAGE = "MESSAGE";

    private final URI url;
    private final String originatorId;
    private final String profileId;
    private final Duration timeout;
    private final HttpClient http;

    public GoSignClient(String url, String originatorId, String profileId, int timeoutMs,
                        String truststorePath, String truststorePassword) {
        if (url == null || url.isBlank() || originatorId == null || originatorId.isBlank()
                || profileId == null || profileId.isBlank()) {
            throw new IllegalStateException("signing.gosign needs url, originator_id and profile_id");
        }
        this.url = URI.create(url.trim());
        this.originatorId = originatorId.trim();
        this.profileId = profileId.trim();
        this.timeout = Duration.ofMillis(Math.max(1000, timeoutMs));
        // HTTP/1.1 only, as for the TSA and OCSP clients: an h2 upgrade offer
        // gets the connection dropped by servers that do not speak it.
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(this.timeout)
                .sslContext(sslContext(truststorePath, truststorePassword))
                .build();
    }

    /** For tests, which bring their own client pointed at a local server. */
    GoSignClient(String url, String originatorId, String profileId, int timeoutMs, HttpClient http) {
        this.url = URI.create(url);
        this.originatorId = originatorId;
        this.profileId = profileId;
        this.timeout = Duration.ofMillis(Math.max(1000, timeoutMs));
        this.http = http;
    }

    /**
     * A Go>Sign transaction and the snippet that drives it.
     *
     * @param documentId the id inside the snippet's {@code GoSign_SetDocumentID}
     * @param snippet    the HTML the signer's browser has to run
     * @param fieldName  the empty signature field Go>Sign chose, when it named one
     */
    public record Session(String documentId, String snippet, String fieldName) {
    }

    /** Opens a transaction. The body is a stub: see the class comment. */
    public Session openSession(byte[] stub, String requestId) {
        HttpResponse<byte[]> response = send(HttpRequest.newBuilder(url)
                .timeout(timeout)
                .header("Content-Type", "application")
                .header("ORIGINATOR_ID", originatorId)
                .header("PROFILE_ID", profileId)
                .POST(HttpRequest.BodyPublishers.ofByteArray(stub)), requestId);

        String snippet = new String(response.body(), StandardCharsets.UTF_8);
        requireSuccess(response, snippet, requestId);
        String documentId = group(DOCUMENT_ID, snippet).orElseThrow(() -> new OrchestratorException(
                ErrorCode.GOSIGN_REJECTED, "the response carries no document id"));
        log.info("[{}] Go>Sign session open, document id ends {}", requestId, tail(documentId));
        return new Session(documentId, snippet, group(FIELD_NAME, snippet).orElse(null));
    }

    /**
     * Registers the digest the token is to sign.
     *
     * @return the {@code GOSIGN_TRANSACTION_ID} the service reports, which is
     *         not the document id and may be what {@link #download} wants
     */
    public Optional<String> registerHash(String documentId, byte[] digest, String requestId) {
        String encoded = Base64.getEncoder().encodeToString(digest);
        HttpResponse<byte[]> response = send(HttpRequest.newBuilder(url)
                .timeout(timeout)
                .header("Content-Type", "application")
                .header("ORIGINATOR_ID", originatorId)
                .header("PROFILE_ID", profileId)
                .header("REQUEST_TYPE", "SET_HASH")
                .header("TRANSACTION_ID", documentId)
                .POST(HttpRequest.BodyPublishers.ofString(encoded, StandardCharsets.US_ASCII)), requestId);

        // An id the service does not know is answered with 200, no status header
        // and an empty body - silence rather than an error - so the status being
        // absent has to be treated as the failure it is.
        String status = header(response, STATUS).orElseThrow(() -> new OrchestratorException(
                ErrorCode.GOSIGN_REJECTED,
                "the hash was not accepted; the service reported no status for this transaction"));
        if (!"SUCCESS".equals(status.toUpperCase(Locale.ROOT))) {
            throw new OrchestratorException(ErrorCode.GOSIGN_REJECTED,
                    status + header(response, MESSAGE).map(m -> " - " + m).orElse(""));
        }
        log.info("[{}] Go>Sign accepted the {}-byte digest", requestId, digest.length);
        return header(response, "GOSIGN_TRANSACTION_ID");
    }

    /**
     * Whatever the service returns for a transaction once the token has signed.
     *
     * <p>Deliberately untyped: whether this is a bare CMS signature or a PDF the
     * service assembled from the stub has not been confirmed with a physical
     * token, so interpreting it is {@link TokenSignatureSource}'s job, not
     * this client's.</p>
     */
    public byte[] download(String transactionId, String requestId) {
        HttpResponse<byte[]> response = send(HttpRequest.newBuilder(url)
                .timeout(timeout)
                .header("Content-Type", "text/plain")
                .header("TRANSACTION_ID", transactionId)
                .POST(HttpRequest.BodyPublishers.noBody()), requestId);

        String status = header(response, STATUS).orElse("");
        if ("PENDING".equalsIgnoreCase(status)) {
            throw new OrchestratorException(ErrorCode.TOKEN_SESSION_PENDING);
        }
        if ("DECLINED".equalsIgnoreCase(status)) {
            throw new OrchestratorException(ErrorCode.AUTHORISATION_DECLINED);
        }
        if (response.statusCode() != 200) {
            throw new OrchestratorException(ErrorCode.GOSIGN_REJECTED,
                    "HTTP " + response.statusCode() + header(response, MESSAGE).map(m -> " - " + m).orElse(""));
        }
        byte[] body = response.body();
        if (body == null || body.length == 0) {
            // The token has not signed yet: the service holds the transaction
            // but has nothing to give back.
            throw new OrchestratorException(ErrorCode.TOKEN_SESSION_PENDING);
        }
        log.info("[{}] Go>Sign returned {} bytes for transaction ending {}",
                requestId, body.length, tail(transactionId));
        return body;
    }

    private void requireSuccess(HttpResponse<byte[]> response, String body, String requestId) {
        String status = header(response, STATUS).orElse("");
        if ("SUCCESS".equalsIgnoreCase(status) && response.statusCode() == 200 && !body.isBlank()) {
            return;
        }
        String message = header(response, MESSAGE).orElse("");
        log.warn("[{}] Go>Sign refused the request: HTTP {} {} {}",
                requestId, response.statusCode(), status, message);
        throw new OrchestratorException(ErrorCode.GOSIGN_REJECTED,
                (status.isBlank() ? "HTTP " + response.statusCode() : status)
                        + (message.isBlank() ? "" : " - " + message));
    }

    private HttpResponse<byte[]> send(HttpRequest.Builder request, String requestId) {
        try {
            return http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OrchestratorException(ErrorCode.GOSIGN_UNAVAILABLE, "interrupted");
        } catch (Exception e) {
            log.warn("[{}] Go>Sign at {} is not reachable: {}", requestId, url, e.toString());
            throw new OrchestratorException(ErrorCode.GOSIGN_UNAVAILABLE,
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static Optional<String> header(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(String::trim).filter(v -> !v.isEmpty());
    }

    private static Optional<String> group(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    /** Transaction ids identify a signing session; only their tail is logged. */
    private static String tail(String id) {
        return id == null || id.length() < 6 ? "?" : id.substring(id.length() - 6);
    }

    public String url() {
        return url.toString();
    }

    public String profileId() {
        return profileId;
    }

    /**
     * Trusts the configured truststore in addition to the JVM's authorities.
     * Mirrors {@code TsaClient} rather than sharing with it, to leave the
     * timestamp path untouched.
     */
    private static SSLContext sslContext(String truststorePath, String truststorePassword) {
        try {
            X509TrustManager configured = truststorePath == null || truststorePath.isBlank()
                    ? null : trustManager(truststorePath, truststorePassword);
            SSLContext context = SSLContext.getInstance("TLS");
            if (configured == null) {
                context.init(null, null, new SecureRandom());
                return context;
            }
            X509TrustManager jvm = trustManager(null, null);
            context.init(null, new TrustManager[]{either(configured, jvm)}, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot build the TLS context for Go>Sign: " + e.getMessage(), e);
        }
    }

    private static X509TrustManager trustManager(String path, String password) throws Exception {
        KeyStore store = null;
        if (path != null) {
            store = KeyStore.getInstance(path.toLowerCase(Locale.ROOT).endsWith(".jks") ? "JKS" : "PKCS12");
            try (InputStream in = new FileInputStream(path)) {
                store.load(in, password == null ? new char[0] : password.toCharArray());
            }
        }
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException("no X509TrustManager available");
    }

    /** Accepts a server either truststore trusts, so neither has to hold both. */
    private static X509TrustManager either(X509TrustManager first, X509TrustManager second) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                first.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                try {
                    first.checkServerTrusted(chain, authType);
                } catch (java.security.cert.CertificateException e) {
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
