package iq.twokeyok.orchestrator.signing.gosign;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;

/**
 * The documents waiting for a token to sign them.
 *
 * <p>A prepared document cannot be returned to the caller - it carries a
 * signature placeholder and the digest Go>Sign was given, and handing it out
 * would let a caller sign something other than what was prepared. So it stays
 * here, keyed by an opaque session id, until the second call collects it.</p>
 *
 * <p>In memory on purpose: a prepared document is worthless once its Go>Sign
 * transaction expires, so surviving a restart buys nothing. It does mean
 * sessions do not survive a restart or span instances, which the API documents
 * as a restart losing in-flight preparations.</p>
 */
@Component
public class TokenSigningSessionStore {

    private static final Logger log = LoggerFactory.getLogger(TokenSigningSessionStore.class);

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Duration ttl;
    private final int maxSessions;

    @Autowired
    public TokenSigningSessionStore(SigningProperties properties) {
        SigningProperties.GoSign config = properties.gosign();
        this.ttl = Duration.ofSeconds(config == null ? 900 : Math.max(60, config.sessionTtlSeconds()));
        this.maxSessions = config == null ? 50 : Math.max(1, config.maxConcurrentSessions());
    }

    public TokenSigningSessionStore(Duration ttl, int maxSessions) {
        this.ttl = ttl;
        this.maxSessions = maxSessions;
    }

    /**
     * One document prepared for one token signature.
     *
     * <p>{@code completed} makes collection single-use: a repeated second call
     * is a duplicate, not a second signature, and must not start another Go>Sign
     * download or return a document twice.</p>
     */
    public static final class Session {

        private final String id;
        private final String requestId;
        private final String callerId;
        private final String signerId;
        private final String fileName;
        private final EffectiveSignerConfig config;
        private final DeferredPdfSignature.Prepared prepared;
        private final TokenSignatureSource.Handle handle;
        private final Instant expiresAt;
        private final AtomicBoolean completed = new AtomicBoolean();

        Session(String id, String requestId, String callerId, String signerId, String fileName,
                EffectiveSignerConfig config, DeferredPdfSignature.Prepared prepared,
                TokenSignatureSource.Handle handle, Instant expiresAt) {
            this.id = id;
            this.requestId = requestId;
            this.callerId = callerId;
            this.signerId = signerId;
            this.fileName = fileName;
            this.config = config;
            this.prepared = prepared;
            this.handle = handle;
            this.expiresAt = expiresAt;
        }

        public String id() {
            return id;
        }

        public String requestId() {
            return requestId;
        }

        public String callerId() {
            return callerId;
        }

        public String signerId() {
            return signerId;
        }

        public String fileName() {
            return fileName;
        }

        public EffectiveSignerConfig config() {
            return config;
        }

        public DeferredPdfSignature.Prepared prepared() {
            return prepared;
        }

        public TokenSignatureSource.Handle handle() {
            return handle;
        }

        public Instant expiresAt() {
            return expiresAt;
        }

        boolean isExpired(Instant now) {
            return now.isAfter(expiresAt);
        }

        /** @return whether this call is the one that may complete the session */
        boolean claim() {
            return completed.compareAndSet(false, true);
        }
    }

    /**
     * @throws OrchestratorException {@code 1137} when the store already holds as
     *                               many prepared documents as it is allowed to
     */
    public Session open(String requestId, String callerId, String signerId, String fileName,
                        EffectiveSignerConfig config, DeferredPdfSignature.Prepared prepared,
                        TokenSignatureSource.Handle handle) {
        evictExpired();
        if (sessions.size() >= maxSessions) {
            log.warn("[{}] Refusing to prepare: {} sessions are already waiting for a token",
                    requestId, sessions.size());
            throw new OrchestratorException(ErrorCode.TOKEN_SESSION_LIMIT);
        }
        String id = UUID.randomUUID().toString();
        Session session = new Session(id, requestId, callerId, signerId, fileName, config, prepared, handle,
                Instant.now().plus(ttl));
        sessions.put(id, session);
        log.info("[{}] Prepared {} for signing as [{}], session expires {}",
                requestId, fileName, signerId, session.expiresAt());
        return session;
    }

    /**
     * The session {@code callerId} may complete, claimed so that only one of
     * several concurrent calls proceeds.
     *
     * @throws OrchestratorException {@code 1134} unknown or expired,
     *                               {@code 1136} already completed
     */
    public Session claim(String id, String callerId) {
        evictExpired();
        Session session = sessions.get(id);
        // A session belonging to another caller is reported as unknown rather
        // than forbidden: whether an id exists is not something to disclose.
        if (session == null || !session.callerId().equals(callerId)) {
            throw new OrchestratorException(ErrorCode.TOKEN_SESSION_UNKNOWN, id);
        }
        if (session.isExpired(Instant.now())) {
            sessions.remove(id);
            throw new OrchestratorException(ErrorCode.TOKEN_SESSION_UNKNOWN, id);
        }
        if (!session.claim()) {
            throw new OrchestratorException(ErrorCode.TOKEN_SESSION_SPENT, id);
        }
        return session;
    }

    /**
     * Hands a claimed session back for another attempt. A token that has not
     * signed yet is not a spent session: the caller is told to retry, and must
     * be able to.
     */
    public void release(Session session) {
        session.completed.set(false);
    }

    /** Drops a session whose document has been collected, or which failed for good. */
    public void close(Session session) {
        sessions.remove(session.id());
    }

    public Optional<Session> peek(String id) {
        return Optional.ofNullable(sessions.get(id));
    }

    public int size() {
        evictExpired();
        return sessions.size();
    }

    private void evictExpired() {
        Instant now = Instant.now();
        List<String> expired = sessions.values().stream()
                .filter(session -> session.isExpired(now))
                .map(Session::id)
                .toList();
        for (String id : expired) {
            Session removed = sessions.remove(id);
            if (removed != null) {
                log.info("[{}] Prepared document expired before the token signed it", removed.requestId());
            }
        }
    }
}
