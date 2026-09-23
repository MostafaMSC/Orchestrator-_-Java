package iq.twokeyok.orchestrator.security;

import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * Validates the signer access token issued by the customer IAM (Keycloak, Entra
 * ID, …) and maps its claims onto a signer identity.
 *
 * <p>Signature, issuer, audience and expiry are checked against the JWKS
 * advertised by the IAM; the keys are cached for
 * {@code orchestrator.security.bearer.jwks-cache-seconds}.</p>
 */
@Component
public class BearerTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenVerifier.class);

    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

    private final CscProperties.Bearer config;
    private final ConfigurableJWTProcessor<SecurityContext> processor;

    public BearerTokenVerifier(CscProperties properties) {
        this.config = properties.bearer();
        this.processor = config.enabled() ? buildProcessor(config) : null;
        if (config.enabled()) {
            log.info("Signer access tokens will be validated against issuer={} jwks={}",
                    config.issuer(), config.jwksUri());
        }
    }

    public boolean isEnabled() {
        return processor != null;
    }

    /**
     * @return the caller described by the token
     * @throws OrchestratorException with {@link ErrorCode#INVALID_OR_EXPIRED_TOKEN}
     *                               if the token cannot be trusted
     */
    public AuthenticatedCaller verify(String token) {
        if (!isEnabled()) {
            throw new OrchestratorException(ErrorCode.INVALID_OR_EXPIRED_TOKEN);
        }
        JWTClaimsSet claims;
        try {
            claims = processor.process(token, null);
        } catch (Exception e) {
            log.debug("Rejected bearer token: {}", e.getMessage());
            throw new OrchestratorException(ErrorCode.INVALID_OR_EXPIRED_TOKEN, e);
        }

        String signerId = stringClaim(claims, config.signerIdClaim());
        if (signerId == null || signerId.isBlank()) {
            throw new OrchestratorException(ErrorCode.TOKEN_CLAIM_MISSING,
                    config.signerIdClaim(), claims.getSubject());
        }
        String credentialId = config.credentialIdClaim() == null
                ? null : stringClaim(claims, config.credentialIdClaim());
        String clientId = config.clientIdClaim() == null
                ? "bearer" : stringClaim(claims, config.clientIdClaim());

        return AuthenticatedCaller.signer(clientId == null ? "bearer" : clientId, signerId, credentialId);
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        try {
            Object value = claims.getClaim(name);
            return value == null ? null : String.valueOf(value);
        } catch (Exception e) {
            return null;
        }
    }

    private static ConfigurableJWTProcessor<SecurityContext> buildProcessor(CscProperties.Bearer config) {
        if (config.jwksUri() == null || config.jwksUri().isBlank()) {
            throw new IllegalStateException(
                    "csc-config.bearer.enabled is true but jwks-uri is not configured");
        }
        try {
            URL jwksUrl = URI.create(config.jwksUri()).toURL();
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl)
                    .cache(config.jwksCacheSeconds() * 1000L, 15_000L)
                    .build();

            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(
                    new JWSVerificationKeySelector<>(new LinkedHashSet<>(SUPPORTED_ALGORITHMS), jwkSource));

            JWTClaimsSet.Builder exactMatch = new JWTClaimsSet.Builder();
            if (config.issuer() != null && !config.issuer().isBlank()) {
                exactMatch.issuer(config.issuer());
            }
            Set<String> required = new HashSet<>(Set.of("exp"));
            required.add(config.signerIdClaim());

            DefaultJWTClaimsVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(
                    config.audiences().isEmpty() ? null : new HashSet<>(config.audiences()),
                    exactMatch.build(),
                    required,
                    null);
            verifier.setMaxClockSkew((int) config.clockSkewSeconds());
            processor.setJWTClaimsSetVerifier(verifier);
            return processor;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot initialise bearer token validation: " + e.getMessage(), e);
        }
    }

    /** Only used by tests that need to confirm a parse failure is surfaced as 1013. */
    static String unsafePeekSubject(String token) throws ParseException {
        return com.nimbusds.jwt.JWTParser.parse(token).getJWTClaimsSet().getSubject();
    }
}
