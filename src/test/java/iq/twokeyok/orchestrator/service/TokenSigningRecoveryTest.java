package iq.twokeyok.orchestrator.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.appearance.AppearanceService.TextDefaults;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;
import iq.twokeyok.orchestrator.signing.gosign.DeferredPdfSignature;
import iq.twokeyok.orchestrator.signing.gosign.TokenTestSignatures;
import iq.twokeyok.orchestrator.signing.gosign.TokenSignatureSource;
import iq.twokeyok.orchestrator.signing.gosign.TokenSigningSessionStore;
import iq.twokeyok.orchestrator.signing.timestamp.DocumentTimestamper;
import iq.twokeyok.orchestrator.signing.timestamp.TsaClient;

/**
 * How {@code complete} behaves while the signer is still at the token, and once
 * something has gone wrong.
 *
 * <p>The distinction matters: a token that has not signed yet must leave the
 * prepared document collectable, because the caller is expected to come back,
 * while a real failure must consume it - Go>Sign already holds that digest and
 * it cannot be offered for signing twice.</p>
 */
class TokenSigningRecoveryTest {

    private static final AuthenticatedCaller CALLER = new AuthenticatedCaller(
            AuthenticatedCaller.Kind.CLIENT, "hr_portal", null, null, null);

    /** Stands in for Go>Sign: answers from a script the test sets out. */
    private static final class ScriptedSource implements TokenSignatureSource {

        private final AtomicInteger calls = new AtomicInteger();
        private final Object[] answers;

        ScriptedSource(Object... answers) {
            this.answers = answers;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public Handle open(byte[] digest, String requestId) {
            return new Handle("doc-1", "txn-1", "<script/>", "Signature1");
        }

        @Override
        public byte[] fetchCms(Handle handle, String requestId) {
            Object answer = answers[Math.min(calls.getAndIncrement(), answers.length - 1)];
            if (answer instanceof ErrorCode code) {
                throw new OrchestratorException(code);
            }
            return (byte[]) answer;
        }

        int calls() {
            return calls.get();
        }
    }

    private TokenSigningService service(TokenSignatureSource source, TokenSigningSessionStore store) {
        // prepare() is not exercised here, so the resolvers it needs are left
        // out; complete() reaches only the store, the source and the timestamper.
        return new TokenSigningService(null, null, null, source, store,
                new DocumentTimestamper((TsaClient) null), new AuditLogger(), null);
    }

    private static EffectiveSignerConfig config() {
        return new EffectiveSignerConfig("token_signer", SignerType.TOKEN, "barakat",
                "adss:gosign:profile:007", null, "token.user", null, "SHA256", null,
                "ETSI.CAdES.detached", 20000, "Signature1", 1, true, false, null, "NONE", null,
                TextDefaults.EMPTY, true, true, true);
    }

    private TokenSigningSessionStore.Session open(TokenSigningSessionStore store,
                                                  DeferredPdfSignature.Prepared prepared) {
        return store.open("req-1", CALLER.clientId(), "token_signer", "doc.pdf", config(), prepared,
                new TokenSignatureSource.Handle("doc-1", "txn-1", "<script/>", "Signature1"));
    }

    @Test
    void letsTheCallerRetryUntilTheTokenHasSigned() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        byte[] cms = TokenTestSignatures.cmsOver(prepared);
        ScriptedSource source = new ScriptedSource(
                ErrorCode.TOKEN_SESSION_PENDING, ErrorCode.TOKEN_SESSION_PENDING, cms);
        TokenSigningSessionStore store = new TokenSigningSessionStore(Duration.ofMinutes(10), 10);
        TokenSigningService service = service(source, store);
        String id = open(store, prepared).id();

        for (int attempt = 0; attempt < 2; attempt++) {
            assertThatThrownBy(() -> service.complete(CALLER, id))
                    .isInstanceOf(OrchestratorException.class)
                    .extracting(e -> ((OrchestratorException) e).errorCode())
                    .isEqualTo(ErrorCode.TOKEN_SESSION_PENDING);
            assertThat(store.peek(id)).as("a pending token does not spend the session").isPresent();
        }

        TokenSigningService.SignedDocument signed = service.complete(CALLER, id);

        assertThat(signed.content()).isNotEmpty();
        assertThat(signed.fileName()).isEqualTo("doc.pdf");
        assertThat(source.calls()).isEqualTo(3);
        assertThat(store.peek(id)).as("collected, so the session is gone").isEmpty();
    }

    @Test
    void refusesToReturnTheSameSignedDocumentTwice() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        ScriptedSource source = new ScriptedSource(TokenTestSignatures.cmsOver(prepared));
        TokenSigningSessionStore store = new TokenSigningSessionStore(Duration.ofMinutes(10), 10);
        TokenSigningService service = service(source, store);
        String id = open(store, prepared).id();

        service.complete(CALLER, id);

        // The session is gone rather than spent, because a collected document is
        // not kept: the caller is told the session is unknown.
        assertThatThrownBy(() -> service.complete(CALLER, id))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_UNKNOWN);
    }

    @Test
    void givesUpOnASessionWhoseSignatureCanNeverBeUsed() throws Exception {
        // Go>Sign holds the digest for this transaction, so a signature that does
        // not verify cannot be retried into a good one. The session is consumed
        // and the caller has to prepare the document again.
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        ScriptedSource source = new ScriptedSource(
                TokenTestSignatures.cmsOver("some other bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        TokenSigningSessionStore store = new TokenSigningSessionStore(Duration.ofMinutes(10), 10);
        TokenSigningService service = service(source, store);
        String id = open(store, prepared).id();

        assertThatThrownBy(() -> service.complete(CALLER, id))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);

        assertThat(store.peek(id)).as("a failure that cannot be retried consumes the session").isEmpty();
        assertThatThrownBy(() -> service.complete(CALLER, id))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_UNKNOWN);
    }

    @Test
    void closesASessionWhenGoSignCannotBeReached() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        ScriptedSource source = new ScriptedSource(ErrorCode.GOSIGN_UNAVAILABLE);
        TokenSigningSessionStore store = new TokenSigningSessionStore(Duration.ofMinutes(10), 10);
        TokenSigningService service = service(source, store);
        String id = open(store, prepared).id();

        assertThatThrownBy(() -> service.complete(CALLER, id))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.GOSIGN_UNAVAILABLE);
        assertThat(store.peek(id)).isEmpty();
    }

    @Test
    void keepsTwoCallersSigningAtOnceApart() throws Exception {
        DeferredPdfSignature.Prepared first = TokenTestSignatures.prepared("Signature1");
        DeferredPdfSignature.Prepared second = TokenTestSignatures.prepared("Signature1");
        TokenSigningSessionStore store = new TokenSigningSessionStore(Duration.ofMinutes(10), 10);

        String firstId = store.open("req-a", "hr_portal", "token_signer", "a.pdf", config(), first,
                new TokenSignatureSource.Handle("doc-a", "txn-a", "<script/>", "Signature1")).id();
        String secondId = store.open("req-b", "case_management", "token_signer", "b.pdf", config(), second,
                new TokenSignatureSource.Handle("doc-b", "txn-b", "<script/>", "Signature1")).id();

        TokenSigningService service = service(new ScriptedSource(TokenTestSignatures.cmsOver(first)), store);
        assertThat(service.complete(CALLER, firstId).fileName()).isEqualTo("a.pdf");

        // The other caller's session is untouched, and this caller cannot reach it.
        assertThat(store.peek(secondId)).isPresent();
        assertThatThrownBy(() -> service.complete(CALLER, secondId))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_UNKNOWN);
    }

    @Test
    void forgetsAPreparedDocumentNobodySignedInTime() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        TokenSigningSessionStore store = new TokenSigningSessionStore(Duration.ofSeconds(-1), 10);
        TokenSigningService service = service(new ScriptedSource(TokenTestSignatures.cmsOver(prepared)), store);
        String id = open(store, prepared).id();

        assertThatThrownBy(() -> service.complete(CALLER, id))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_UNKNOWN);
    }
}
