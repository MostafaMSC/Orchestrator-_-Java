package iq.twokeyok.orchestrator.security;

/**
 * Who is calling the orchestrator.
 *
 * <p>{@link Kind#CLIENT} is a business application authenticating with
 * {@code Basic base64(clientId:clientSecret)}; it must name the signer it acts
 * for. {@link Kind#SIGNER} is an end user presenting their own IAM access token;
 * the signer identity comes from the token, not from the request body.</p>
 *
 * @param kind        how the caller authenticated
 * @param clientId    orchestrator client id (always present)
 * @param signerId    signer taken from the access token, {@code null} for CLIENT
 * @param credentialId credential id taken from the access token, may be {@code null}
 */
public record AuthenticatedCaller(Kind kind, String clientId, String signerId, String credentialId) {

    public enum Kind {
        CLIENT,
        SIGNER,
        ANONYMOUS
    }

    public static AuthenticatedCaller client(String clientId) {
        return new AuthenticatedCaller(Kind.CLIENT, clientId, null, null);
    }

    public static AuthenticatedCaller signer(String clientId, String signerId, String credentialId) {
        return new AuthenticatedCaller(Kind.SIGNER, clientId, signerId, credentialId);
    }

    public static AuthenticatedCaller anonymous() {
        return new AuthenticatedCaller(Kind.ANONYMOUS, "anonymous", null, null);
    }

    public boolean isSigner() {
        return kind == Kind.SIGNER;
    }
}
