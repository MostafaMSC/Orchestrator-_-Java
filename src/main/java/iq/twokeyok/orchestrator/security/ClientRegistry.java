package iq.twokeyok.orchestrator.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.config.CscProperties.RegisteredClient;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * The business applications registered under {@code csc-config.registered-clients}.
 *
 * <p>A secret is matched against {@code secret-hash} with BCrypt when one is
 * configured, and against {@code client-secret} in constant time otherwise. The
 * plain form exists because the reference configuration uses it — usually
 * wrapped as {@code ENC(...)}, which Jasypt decrypts before binding — but a
 * hash is preferable because it stays useless to anyone who reads the file.</p>
 */
@Component
public class ClientRegistry {

    private static final Logger log = LoggerFactory.getLogger(ClientRegistry.class);

    private final Map<String, RegisteredClient> clients = new LinkedHashMap<>();
    private final String defaultAdssClientId;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public ClientRegistry(CscProperties cscProperties, SigningProperties signingProperties) {
        this.defaultAdssClientId = signingProperties.gateway().clientId();

        for (RegisteredClient client : cscProperties.registeredClients()) {
            if (client.clientId() == null || client.clientId().isBlank()) {
                log.warn("Ignoring a registered client without client-id");
                continue;
            }
            if (clients.putIfAbsent(client.clientId(), client) != null) {
                log.warn("Duplicate client-id '{}' in csc-config.registered-clients; keeping the first",
                        client.clientId());
                continue;
            }
            if (client.secretHash() == null && client.clientSecret() != null) {
                log.warn("Client '{}' is configured with a reversible secret. Prefer 'secret-hash' "
                        + "(generate one with --hash-secret).", client.clientId());
            }
        }
        log.info("Loaded {} registered client(s): {}", clients.size(), clients.keySet());
    }

    public Optional<RegisteredClient> find(String clientId) {
        return Optional.ofNullable(clients.get(clientId));
    }

    /**
     * @throws OrchestratorException 1005 when the client id is unknown or disabled,
     *                               1009 when the secret does not match
     */
    public RegisteredClient authenticate(String clientId, String clientSecret) {
        RegisteredClient client = clients.get(clientId);
        if (client == null || !client.enabled()) {
            throw new OrchestratorException(ErrorCode.INVALID_CLIENT_ID);
        }
        if (!secretMatches(client, clientSecret)) {
            throw new OrchestratorException(ErrorCode.INVALID_CLIENT_CREDENTIALS);
        }
        return client;
    }

    private boolean secretMatches(RegisteredClient client, String presented) {
        if (presented == null) {
            return false;
        }
        if (client.secretHash() != null && !client.secretHash().isBlank()) {
            return encoder.matches(presented, client.secretHash());
        }
        if (client.clientSecret() != null && !client.clientSecret().isBlank()) {
            return constantTimeEquals(client.clientSecret(), presented);
        }
        return false;
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    /** ADSS originator id for this client, falling back to {@code signing.gateway.client_id}. */
    public String adssClientId(String clientId) {
        return find(clientId)
                .map(RegisteredClient::adssClientId)
                .filter(value -> value != null && !value.isBlank())
                .orElse(defaultAdssClientId);
    }
}
