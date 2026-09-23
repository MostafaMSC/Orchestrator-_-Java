package iq.twokeyok.orchestrator.signing;

import java.util.List;

import iq.twokeyok.orchestrator.appearance.ResolvedAppearance;

/**
 * One signing request, fully resolved and validated, ready for the backend.
 *
 * @param requestId   correlation id echoed into logs and the audit trail
 * @param config      the resolved signer configuration
 * @param appearance  the resolved visible signature
 * @param documents   input documents, in the order the caller sent them
 */
public record SignJob(String requestId,
                      EffectiveSignerConfig config,
                      ResolvedAppearance appearance,
                      List<SignDocument> documents) {

    /**
     * @param fileName    original file name, reused for the signed output
     * @param contentType declared content type
     * @param content     document bytes
     */
    public record SignDocument(String fileName, String contentType, byte[] content) {
    }

    /** @param documents the signed documents, aligned with the input order */
    public record SignResult(List<SignedDocument> documents, String transactionId) {

        public record SignedDocument(String fileName, byte[] content) {
        }
    }
}
