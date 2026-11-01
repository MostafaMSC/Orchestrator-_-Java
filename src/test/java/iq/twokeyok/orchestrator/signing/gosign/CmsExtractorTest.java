package iq.twokeyok.orchestrator.signing.gosign;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * What Go>Sign returns once a token has signed is not confirmed, so both forms
 * it could take are read and anything else is refused. These cases are the
 * reason retrieval is behind an interface at all.
 */
class CmsExtractorTest {

    @Test
    void takesACmsSignatureAsItComes() throws Exception {
        byte[] cms = TokenTestSignatures.cmsOver("content".getBytes(StandardCharsets.UTF_8));

        assertThat(CmsExtractor.extract(cms)).isEqualTo(cms);
    }

    @Test
    void takesTheSignatureOutOfADocumentTheServiceAssembled() throws Exception {
        // The service's usual mode assembles the signature into a document. Built
        // from our stub it is of no use, but the signature inside it is the one
        // over our digest, so that is what is taken.
        DeferredPdfSignature.Prepared prepared = TokenTestSignatures.prepared("Signature1");
        byte[] signedPdf = DeferredPdfSignature.inject(prepared, TokenTestSignatures.cmsOver(prepared));

        byte[] extracted = CmsExtractor.extract(signedPdf);

        assertThat(extracted).isNotEmpty();
        // Re-encoded as DER, so it need not be byte-identical to what went in.
        // What matters is that it still verifies over the prepared document,
        // which is what inject refuses to do for anything else.
        assertThatCode(() -> DeferredPdfSignature.inject(prepared, extracted))
                .as("what came out is a signature over the prepared document")
                .doesNotThrowAnyException();
    }

    @Test
    void refusesAnErrorPage() {
        // A Tomcat error page is what the staging service returns for a
        // transaction it does not know; injecting it would produce a document
        // that claims to be signed.
        byte[] html = "<!doctype html><html><body>HTTP Status 500</body></html>"
                .getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> CmsExtractor.extract(html))
                .isInstanceOf(OrchestratorException.class)
                .hasMessageContaining("neither a signed PDF nor a CMS")
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);
    }

    @Test
    void refusesAnEmptyBody() {
        assertThatThrownBy(() -> CmsExtractor.extract(new byte[0]))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);
    }

    @Test
    void refusesADocumentThatCarriesNoSignature() throws Exception {
        assertThatThrownBy(() -> CmsExtractor.extract(TokenTestSignatures.blankPdf()))
                .isInstanceOf(OrchestratorException.class)
                .hasMessageContaining("no signature")
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TOKEN_SIGNATURE_INVALID);
    }
}
