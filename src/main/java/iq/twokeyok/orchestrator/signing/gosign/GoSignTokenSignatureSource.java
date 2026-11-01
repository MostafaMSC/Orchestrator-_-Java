package iq.twokeyok.orchestrator.signing.gosign;

import java.io.ByteArrayOutputStream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * {@link TokenSignatureSource} over the ADSS Go>Sign Service.
 *
 * <p>Go>Sign will not open a transaction without a document in the body, and
 * {@code SET_HASH} cannot open one. So a transaction is opened with a one-page
 * stub and the real digest registered against it - the digest need not belong to
 * the uploaded document, which was established against the staging service. The
 * document being signed therefore never leaves this host; what Go>Sign holds is
 * a blank page and a digest.</p>
 */
@Component
public class GoSignTokenSignatureSource implements TokenSignatureSource {

    private static final Logger log = LoggerFactory.getLogger(GoSignTokenSignatureSource.class);

    private final GoSignClient client;
    private final byte[] stub;

    @Autowired
    public GoSignTokenSignatureSource(SigningProperties properties) {
        SigningProperties.GoSign config = properties.gosign();
        boolean configured = config != null && config.url() != null && !config.url().isBlank()
                && config.originatorId() != null && !config.originatorId().isBlank()
                && config.profileId() != null && !config.profileId().isBlank();
        this.client = configured
                ? new GoSignClient(config.url(), config.originatorId(), config.profileId(), config.timeoutMs(),
                        properties.truststorePath(), properties.truststorePassword())
                : null;
        this.stub = configured ? stubDocument() : null;
        if (configured) {
            log.info("Token signing is available through Go>Sign at {} with profile {}",
                    client.url(), client.profileId());
        }
    }

    /** For tests and for a deployment that brings its own client. */
    public GoSignTokenSignatureSource(GoSignClient client) {
        this.client = client;
        this.stub = client == null ? null : stubDocument();
    }

    @Override
    public boolean isEnabled() {
        return client != null;
    }

    @Override
    public Handle open(byte[] digest, String requestId) {
        requireEnabled();
        if (digest == null || digest.length == 0) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNATURE_INVALID, "no digest to register");
        }
        GoSignClient.Session session = client.openSession(stub, requestId);
        String transactionId = client.registerHash(session.documentId(), digest, requestId).orElse(null);
        return new Handle(session.documentId(), transactionId, session.snippet(), session.fieldName());
    }

    @Override
    public byte[] fetchCms(Handle handle, String requestId) {
        requireEnabled();
        // The document id is what the snippet drives and what the guide's own
        // download example uses. The service's separate GOSIGN_TRANSACTION_ID is
        // tried after it, because which one the download accepts in SET_HASH
        // mode is not documented.
        try {
            return CmsExtractor.extract(client.download(handle.documentId(), requestId));
        } catch (OrchestratorException e) {
            if (e.errorCode() == ErrorCode.TOKEN_SESSION_PENDING
                    || handle.transactionId() == null
                    || handle.transactionId().equals(handle.documentId())) {
                throw e;
            }
            log.info("[{}] The document id was not accepted for download ({}); trying the transaction id",
                    requestId, e.getMessage());
            return CmsExtractor.extract(client.download(handle.transactionId(), requestId));
        }
    }

    private void requireEnabled() {
        if (client == null) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNING_NOT_CONFIGURED);
        }
    }

    /**
     * A one-page blank PDF, the smallest thing Go>Sign accepts as a document.
     * It exists only so a transaction can be opened; nothing is ever read back
     * out of it.
     */
    private static byte[] stubDocument() {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage(PDRectangle.A4));
            ByteArrayOutputStream out = new ByteArrayOutputStream(2048);
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot build the Go>Sign stub document: " + e.getMessage(), e);
        }
    }
}
