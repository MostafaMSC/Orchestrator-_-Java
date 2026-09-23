package iq.twokeyok.orchestrator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;

/**
 * Writes the signing audit trail to the dedicated {@code AUDIT} logger, which
 * {@code logback-spring.xml} sends to its own file.
 *
 * <p>Only identifiers are recorded — never a PIN, a token, a document or a
 * signature.</p>
 */
@Component
public class AuditLogger {

    private static final Logger audit = LoggerFactory.getLogger("AUDIT");

    public void signed(String requestId,
                       AuthenticatedCaller caller,
                       EffectiveSignerConfig config,
                       int documentCount,
                       String transactionId,
                       long elapsedMs) {
        audit.info("event=SIGN_OK request={} client={} auth={} signer={} type={} profile={} credential={} "
                        + "documents={} transaction={} elapsed_ms={}",
                requestId, caller.clientId(), caller.kind(), config.signerId(), config.type(),
                config.profileId(), config.certificateAlias(), documentCount,
                transactionId == null ? "-" : transactionId, elapsedMs);
    }

    public void failed(String requestId,
                       AuthenticatedCaller caller,
                       EffectiveSignerConfig config,
                       ErrorCode errorCode,
                       String description) {
        audit.warn("event=SIGN_FAILED request={} client={} auth={} signer={} error_code={} error=\"{}\"",
                requestId, caller.clientId(), caller.kind(),
                config == null ? "-" : config.signerId(), errorCode.code(), description);
    }
}
