package iq.twokeyok.orchestrator.security;

/**
 * Who is calling the orchestrator.
 *
 * <p>{@link Kind#CLIENT} is a business application authenticating with
 * {@code Basic base64(clientId:clientSecret)}; it must name the signer it acts
 * for. {@link Kind#SIGNER} is the signer themselves — either presenting an IAM
 * access token, or, under {@code signing.basic_auth_type: implicit}, presenting
 * {@code Basic base64(signerId:credentialPassword)} so the identity and the
 * credential password both arrive in the authorization header. Either way the
 * signer identity comes from the credentials, not from the request body.</p>
 *
 * @param kind        how the caller authenticated
 * @param clientId    orchestrator client id (always present)
 * @param signerId    signer taken from the credentials, {@code null} for CLIENT
 * @param credentialId credential id taken from the access token, may be {@code null}
 * @param credentialPassword credential password from implicit Basic auth, {@code null}
 *                           otherwise. Used as the PIN when the request carries none.
 */
public record AuthenticatedCaller(Kind kind,
                                  String clientId,
                                  String signerId,
                                  String credentialId,
                                  String credentialPassword) {

    public enum Kind {
        CLIENT,
        SIGNER,
        ANONYMOUS
    }

    public static AuthenticatedCaller client(String clientId) {
        return new AuthenticatedCaller(Kind.CLIENT, clientId, null, null, null);
    }

    public static AuthenticatedCaller signer(String clientId, String signerId, String credentialId) {
        return new AuthenticatedCaller(Kind.SIGNER, clientId, signerId, credentialId, null);
    }

    /**
     * A signer who authenticated with {@code Basic base64(signerId:password)}.
     *
     * <p>This is the scheme the deployed Ascertia Orchestrator uses, so a caller
     * written against that API works here unchanged. The password is the signer's
     * credential password and is forwarded to ADSS as the PIN; nothing else reads
     * it, and it is never logged or audited.</p>
     */
    public static AuthenticatedCaller implicitSigner(String signerId, String credentialPassword) {
        return new AuthenticatedCaller(Kind.SIGNER, signerId, signerId, null, credentialPassword);
    }

    public static AuthenticatedCaller anonymous() {
        return new AuthenticatedCaller(Kind.ANONYMOUS, "anonymous", null, null, null);
    }

    public boolean isSigner() {
        return kind == Kind.SIGNER;
    }

    public boolean hasCredentialPassword() {
        return credentialPassword != null && !credentialPassword.isBlank();
    }

    /**
     * Redacted on purpose: a record's generated {@code toString} would print the
     * credential password into any log line that formats the caller.
     */
    @Override
    public String toString() {
        return "AuthenticatedCaller[kind=%s, clientId=%s, signerId=%s, credentialId=%s, credentialPassword=%s]"
                .formatted(kind, clientId, signerId, credentialId,
                        hasCredentialPassword() ? "<redacted>" : "null");
    }
}
