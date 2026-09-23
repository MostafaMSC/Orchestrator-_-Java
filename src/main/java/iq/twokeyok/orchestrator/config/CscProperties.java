package iq.twokeyok.orchestrator.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import iq.twokeyok.orchestrator.config.SigningProperties.SigningOverrides;

/**
 * Caller configuration, bound from {@code csc-config.*} to match the deployed
 * Ascertia Orchestrator, where the business applications allowed to call the
 * service are listed under {@code csc-config.registered-clients}.
 *
 * <p>Secrets may be written as {@code ENC(...)} — Jasypt decrypts them before
 * binding — or, preferably, as a BCrypt hash in {@code secret-hash}, which is
 * never reversible even if the configuration leaks.</p>
 */
@ConfigurationProperties(prefix = "csc-config")
public record CscProperties(
        @DefaultValue("true") boolean requireAuthentication,
        @DefaultValue("60") long cacheExpiry,
        @DefaultValue CscV1Info cscV1Info,
        @DefaultValue Bearer bearer,
        List<RegisteredClient> registeredClients) {

    public CscProperties {
        registeredClients = registeredClients == null ? new ArrayList<>() : registeredClients;
    }

    /** Service metadata, as returned by the CSC {@code info} endpoint. */
    public record CscV1Info(
            @DefaultValue("1.0.4.0") String specs,
            String name,
            String logo,
            String region,
            String description,
            String oauth2,
            String idpAuthorize,
            String idpClientId,
            String idpClientSecret) {
    }

    /**
     * Validation of signer access tokens issued by the customer IAM.
     *
     * <p>Only asymmetric algorithms are accepted: a shared secret is not an
     * adequate basis for authorising a signature.</p>
     */
    public record Bearer(
            @DefaultValue("false") boolean enabled,
            String issuer,
            String jwksUri,
            List<String> audiences,
            @DefaultValue("sub") String signerIdClaim,
            String credentialIdClaim,
            String clientIdClaim,
            @DefaultValue("60") long clockSkewSeconds,
            @DefaultValue("300") long jwksCacheSeconds) {

        public Bearer {
            audiences = audiences == null ? List.of() : audiences;
        }
    }

    /** A business application authenticating with {@code Basic base64(id:secret)}. */
    public record RegisteredClient(
            String clientId,
            /** Plain or {@code ENC(...)} secret, as in the reference configuration. */
            String clientSecret,
            /** BCrypt hash; preferred over {@link #clientSecret()}. */
            String secretHash,
            @DefaultValue("true") boolean enabled,
            String displayName,
            List<String> authorities,
            /** ADSS originator id; defaults to {@code signing.gateway.client_id}. */
            String adssClientId,
            /** Used when the request omits {@code signer_id}. */
            String defaultSignerId,
            /** Whitelist; empty means any configured signer. */
            List<String> allowedSignerIds,
            @DefaultValue SigningOverrides overrides) {

        public RegisteredClient {
            authorities = authorities == null ? List.of() : authorities;
            allowedSignerIds = allowedSignerIds == null ? List.of() : allowedSignerIds;
        }
    }
}
