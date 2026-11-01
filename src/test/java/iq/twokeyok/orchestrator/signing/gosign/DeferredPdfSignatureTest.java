package iq.twokeyok.orchestrator.signing.gosign;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.ops.PdfSignatureInspector;

/**
 * The two halves of a token signature have to fit exactly: the digest handed to
 * Go>Sign must be of what the signature ends up covering, and the signature must
 * go back into the gap that digest was taken around. Everything here is about
 * refusing to produce a document that merely looks signed.
 */
class DeferredPdfSignatureTest {

    @TempDir
    Path dir;

    @Test
    void producesADocumentWhoseSignatureVerifies() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");

        assertThat(prepared.digest()).as("SHA-256 of the covered bytes").hasSize(32);
        assertThat(MessageDigest.getInstance("SHA-256")
                .digest(DeferredPdfSignature.covered(prepared.pdf())))
                .as("the digest registered is of what the signature covers")
                .isEqualTo(prepared.digest());

        byte[] signed = DeferredPdfSignature.inject(prepared, TokenTestSignatures.cmsOver(prepared));

        assertThat(signed).hasSameSizeAs(prepared.pdf());
        Path file = Files.write(dir.resolve("token-signed.pdf"), signed);
        assertThat(PdfSignatureInspector.inspect(file.toString()))
                .as("the orchestrator's own verifier accepts it").isZero();
    }

    @Test
    void leavesEveryByteTheDigestCoveredWhereItWas() throws Exception {
        // Filling /Contents must change nothing the digest covered, or the
        // signature would not verify over the document it was made for.
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        byte[] signed = DeferredPdfSignature.inject(prepared, TokenTestSignatures.cmsOver(prepared));

        assertThat(DeferredPdfSignature.covered(signed))
                .isEqualTo(DeferredPdfSignature.covered(prepared.pdf()));
    }

    @Test
    void refusesASignatureMadeOverDifferentBytes() throws Exception {
        // A token that signed something else - the stub, say - must not produce
        // a document this orchestrator calls signed.
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        byte[] wrong = TokenTestSignatures.cmsOver("not this document".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> DeferredPdfSignature.inject(prepared, wrong))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);
    }

    @Test
    void refusesASignatureTooLargeForTheReservedGap() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        byte[] enormous = new byte[64_000];

        assertThatThrownBy(() -> DeferredPdfSignature.inject(prepared, enormous))
                .isInstanceOf(OrchestratorException.class)
                .hasMessageContaining("signature_size")
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);
    }

    @Test
    void refusesAnEmptySignature() throws Exception {
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");

        assertThatThrownBy(() -> DeferredPdfSignature.inject(prepared, new byte[0]))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);
    }

    @Test
    void noticesWhenThePreparedDocumentChangedWhileItWaited() throws Exception {
        // The digest is re-derived from the stored bytes on the way out rather
        // than trusted, so a prepared document that was altered in the meantime
        // is caught instead of being signed as if it were the original.
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        byte[] cms = TokenTestSignatures.cmsOver(prepared);

        byte[] altered = prepared.pdf().clone();
        // Near the end, so the change is certainly inside what /ByteRange
        // covers rather than in the excluded /Contents gap.
        altered[altered.length - 10] ^= 0x5A;
        DeferredPdfSignature.Prepared tampered = new DeferredPdfSignature.Prepared(
                altered, prepared.digest(), prepared.fieldName(), prepared.digestName());

        assertThatThrownBy(() -> DeferredPdfSignature.inject(tampered, cms))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_DOCUMENT_TAMPERED);
    }

    @Test
    void rejectsAHashAlgorithmItCannotUse() throws Exception {
        byte[] withField = TokenTestSignatures.withField("Signature1");

        assertThatThrownBy(() -> DeferredPdfSignature.prepare(withField, "Signature1",
                "ETSI.CAdES.detached", "MD5", 20000, null))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.UNSUPPORTED_HASH_ALGORITHM);
    }
}
