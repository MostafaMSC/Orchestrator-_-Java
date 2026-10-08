package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult.SignedDocument;

/**
 * Appends a PAdES document timestamp to a signed PDF: an incremental update
 * holding a {@code /Type /DocTimeStamp} signature whose {@code /SubFilter} is
 * {@code /ETSI.RFC3161} and whose contents are the TSA's token over everything
 * before it, the existing signature included.
 *
 * <p>This is the archive timestamp a PAdES-LTA document carries. The existing
 * signature is not touched: an incremental update only appends bytes, so its
 * ByteRange still covers exactly what it covered before.</p>
 *
 * <p>Off unless {@code signing.dss.tsa.document-timestamp} is {@code true}.</p>
 */
@Component
public class DocumentTimestamper {

    private static final Logger log = LoggerFactory.getLogger(DocumentTimestamper.class);

    /**
     * Space reserved for the token. A token with its TSA certificate is a few
     * kilobytes; a chain or a large key needs more, and running out cannot be
     * fixed after the fact.
     */
    private static final int RESERVED_TOKEN_BYTES = 20_000;
    private static final COSName DOC_TIME_STAMP = COSName.getPDFName("DocTimeStamp");
    private static final COSName ETSI_RFC3161 = COSName.getPDFName("ETSI.RFC3161");

    private final TsaClient tsa;
    private final TimestampValidationData validationData;

    @Autowired
    public DocumentTimestamper(SigningProperties properties) {
        SigningProperties.Tsa config = properties.dss().tsa();
        this.tsa = config.documentTimestamp()
                ? new TsaClient(config.url(), config.policyId(), config.hashAlgorithm(), config.timeoutMs(),
                        properties.truststorePath(), properties.truststorePassword())
                : null;
        this.validationData = tsa != null && config.validationData()
                ? new TimestampValidationData(new OcspClient(config.timeoutMs()))
                : null;
        if (tsa != null) {
            log.info("Signed documents receive a document timestamp from {}{}", tsa.url(),
                    validationData == null ? "" : ", with its validation data in /DSS");
        }
    }

    /** For tests and for callers that bring their own client. */
    public DocumentTimestamper(TsaClient tsa) {
        this(tsa, null);
    }

    public DocumentTimestamper(TsaClient tsa, TimestampValidationData validationData) {
        this.tsa = tsa;
        this.validationData = validationData;
    }

    public boolean isEnabled() {
        return tsa != null;
    }

    public List<SignedDocument> timestampAll(List<SignedDocument> documents, String requestId) {
        List<SignedDocument> result = new ArrayList<>(documents.size());
        for (SignedDocument document : documents) {
            result.add(new SignedDocument(document.fileName(), timestamp(document.content(), requestId)));
        }
        return result;
    }

    /**
     * @return the document with a document timestamp appended
     * @throws OrchestratorException 1129 / 1130 when the TSA cannot be reached or
     *                               refuses; the signature is never returned
     *                               without the timestamp it was configured to carry
     */
    public byte[] timestamp(byte[] pdf, String requestId) {
        if (tsa == null) {
            return pdf;
        }
        TimeStampToken[] granted = new TimeStampToken[1];
        RuntimeException[] failure = new RuntimeException[1];

        try (PDDocument document = PDDocument.load(pdf);
             SignatureOptions options = new SignatureOptions()) {
            PDSignature signature = new PDSignature();
            signature.setType(DOC_TIME_STAMP);
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(ETSI_RFC3161);
            options.setPreferredSignatureSize(RESERVED_TOKEN_BYTES);

            document.addSignature(signature, content -> {
                try {
                    granted[0] = tsa.timestamp(digest(content));
                    return granted[0].getEncoded();
                } catch (RuntimeException e) {
                    // Kept and rethrown below: PDFBox may wrap what escapes here.
                    failure[0] = e;
                    throw new IOException(e.getMessage(), e);
                }
            }, options);

            ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + RESERVED_TOKEN_BYTES * 2 + 4096);
            document.saveIncremental(out);

            log.info("[{}] Document timestamp from {}: serial {} at {}", requestId, tsa.url(),
                    granted[0].getTimeStampInfo().getSerialNumber(), granted[0].getTimeStampInfo().getGenTime());
            byte[] stamped = out.toByteArray();
            return validationData == null ? stamped : validationData.addFor(stamped, granted[0], requestId);
        } catch (IOException | RuntimeException e) {
            if (failure[0] != null) {
                throw failure[0];
            }
            if (e instanceof OrchestratorException orchestratorException) {
                throw orchestratorException;
            }
            log.error("[{}] Could not add the document timestamp", requestId, e);
            throw new OrchestratorException(ErrorCode.INTERNAL_ERROR, e);
        }
    }

    private byte[] digest(InputStream content) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance(tsa.digestAlgorithm());
            byte[] buffer = new byte[8192];
            for (int read; (read = content.read(buffer)) != -1; ) {
                digest.update(buffer, 0, read);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }
}
