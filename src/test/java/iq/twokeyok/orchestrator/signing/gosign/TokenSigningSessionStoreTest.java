package iq.twokeyok.orchestrator.signing.gosign;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * The store holds documents that are already half-signed: the digest is with
 * Go>Sign and the placeholder is cut. Getting its bookkeeping wrong would either
 * lose a prepared document or hand the same one out twice, so expiry, ownership
 * and single-use collection are checked rather than assumed.
 */
class TokenSigningSessionStoreTest {

    private static final String CALLER = "hr_portal";

    private TokenSigningSessionStore store(Duration ttl, int max) {
        return new TokenSigningSessionStore(ttl, max);
    }

    private TokenSigningSessionStore.Session open(TokenSigningSessionStore store, String caller) {
        return store.open("req-" + caller + "-" + System.nanoTime(), caller, "token_signer", "doc.pdf",
                null, null, new TokenSignatureSource.Handle("doc-1", "txn-1", "<script/>", "Signature1"));
    }

    @Test
    void returnsAPreparedSessionToTheCallerThatPreparedIt() {
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 10);
        TokenSigningSessionStore.Session opened = open(store, CALLER);

        assertThat(store.claim(opened.id(), CALLER).id()).isEqualTo(opened.id());
    }

    @Test
    void forgetsASessionOnceItsTimeToSignHasPassed() {
        // A prepared document is worthless after its Go>Sign transaction ends,
        // so it is dropped rather than kept and refused.
        TokenSigningSessionStore store = store(Duration.ofSeconds(-1), 10);
        TokenSigningSessionStore.Session opened = open(store, CALLER);

        assertThatThrownBy(() -> store.claim(opened.id(), CALLER))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_UNKNOWN);
        assertThat(store.peek(opened.id())).as("evicted, not merely refused").isEmpty();
        assertThat(store.size()).isZero();
    }

    @Test
    void treatsAnotherCallersSessionAsOneThatDoesNotExist() {
        // Whether an id exists is not something to disclose to a caller who does
        // not own it, so this is 1134 rather than a forbidden.
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 10);
        TokenSigningSessionStore.Session opened = open(store, CALLER);

        assertThatThrownBy(() -> store.claim(opened.id(), "case_management"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_UNKNOWN);
        assertThat(store.peek(opened.id())).as("the owner's session is left alone").isPresent();
    }

    @Test
    void refusesToCollectTheSameSignatureTwice() {
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 10);
        TokenSigningSessionStore.Session opened = open(store, CALLER);
        store.claim(opened.id(), CALLER);

        assertThatThrownBy(() -> store.claim(opened.id(), CALLER))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_SPENT);
    }

    @Test
    void letsACallerTryAgainWhenTheTokenHasNotSignedYet() {
        // Pending is not a spent session: the signer is still at the token, and
        // the caller has to be able to come back.
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 10);
        TokenSigningSessionStore.Session opened = open(store, CALLER);

        TokenSigningSessionStore.Session first = store.claim(opened.id(), CALLER);
        store.release(first);

        assertThat(store.claim(opened.id(), CALLER).id()).isEqualTo(opened.id());
    }

    @Test
    void onlyOneOfSeveralSimultaneousCollectionsProceeds() throws Exception {
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 10);
        TokenSigningSessionStore.Session opened = open(store, CALLER);

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger claimed = new AtomicInteger();
        AtomicInteger spent = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<Void>> all = java.util.stream.IntStream.range(0, threads)
                    .<Callable<Void>>mapToObj(i -> () -> {
                        start.await();
                        try {
                            store.claim(opened.id(), CALLER);
                            claimed.incrementAndGet();
                        } catch (OrchestratorException e) {
                            if (e.errorCode() == ErrorCode.TOKEN_SESSION_SPENT) {
                                spent.incrementAndGet();
                            }
                        }
                        return null;
                    }).toList();
            List<Future<Void>> futures = all.stream().map(pool::submit).toList();
            start.countDown();
            for (Future<Void> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(claimed.get()).as("exactly one caller may collect the signature").isEqualTo(1);
        assertThat(spent.get()).as("the rest are told it is already taken").isEqualTo(threads - 1);
    }

    @Test
    void keepsConcurrentSessionsApart() {
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 10);
        TokenSigningSessionStore.Session a = open(store, CALLER);
        TokenSigningSessionStore.Session b = open(store, CALLER);
        TokenSigningSessionStore.Session other = open(store, "case_management");

        assertThat(List.of(a.id(), b.id(), other.id())).doesNotHaveDuplicates();
        assertThat(store.size()).isEqualTo(3);
        // Collecting one leaves the others waiting.
        store.close(store.claim(a.id(), CALLER));
        assertThat(store.peek(b.id())).isPresent();
        assertThat(store.peek(other.id())).isPresent();
        assertThat(store.size()).isEqualTo(2);
    }

    @Test
    void refusesToPrepareMoreDocumentsThanItWillHold() {
        // Each prepared document is a PDF held in memory, so the ceiling is real
        // and has to be reported rather than silently exceeded.
        TokenSigningSessionStore store = store(Duration.ofMinutes(10), 2);
        open(store, CALLER);
        open(store, CALLER);

        assertThatThrownBy(() -> open(store, CALLER))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SESSION_LIMIT);
    }

    @Test
    void makesRoomByForgettingSessionsThatCanNoLongerBeSigned() {
        TokenSigningSessionStore store = store(Duration.ofSeconds(-1), 1);
        open(store, CALLER);

        // The expired one is evicted on the way in, so a new preparation fits.
        assertThat(open(store, CALLER)).isNotNull();
    }
}
