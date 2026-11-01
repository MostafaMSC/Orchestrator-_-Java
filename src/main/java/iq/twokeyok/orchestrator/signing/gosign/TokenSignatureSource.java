package iq.twokeyok.orchestrator.signing.gosign;

/**
 * Where the signature over a digest comes from when the key is on the signer's
 * own token.
 *
 * <p>Deliberately an interface. What the Go>Sign Service hands back once a token
 * has signed has not been confirmed with a physical token: the profile declares
 * {@code DETACHED}, which suggests a bare CMS, but the service also assembles
 * signatures into documents in its usual mode, and the developer guide does not
 * say which applies with {@code SET_HASH}. Whichever it turns out to be, the
 * change belongs in an implementation of this interface and nowhere else -
 * {@link TokenSigningService} works in terms of a digest going out and a CMS
 * coming back.</p>
 */
public interface TokenSignatureSource {

    /**
     * A signing transaction that has been given a digest and is waiting for the
     * token.
     *
     * @param documentId    the id the snippet drives, used to collect the result
     * @param transactionId the service's own id for the registration, when it
     *                      reports one; either may be what the download wants
     * @param snippet       the HTML the signer's browser has to run
     * @param fieldName     the signature field the service named, when it did
     */
    record Handle(String documentId, String transactionId, String snippet, String fieldName) {
    }

    /** Whether token signing is configured at all. */
    boolean isEnabled();

    /**
     * Opens a transaction for {@code digest} and returns what the browser needs.
     * The document the digest was taken from is not sent.
     */
    Handle open(byte[] digest, String requestId);

    /**
     * The CMS signature the token produced, or a
     * {@link iq.twokeyok.orchestrator.error.ErrorCode#TOKEN_SESSION_PENDING}
     * failure while it has not signed yet.
     */
    byte[] fetchCms(Handle handle, String requestId);
}
