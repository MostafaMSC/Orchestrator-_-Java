package iq.twokeyok.orchestrator.service;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.fasterxml.jackson.databind.ObjectMapper;

import iq.twokeyok.orchestrator.appearance.AppearanceService;
import iq.twokeyok.orchestrator.appearance.ResolvedAppearance;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;
import iq.twokeyok.orchestrator.signing.SignJob;
import iq.twokeyok.orchestrator.signing.SignatureFieldNames;
import iq.twokeyok.orchestrator.signing.SignerResolver;
import iq.twokeyok.orchestrator.signing.adss.EmptySignatureField;
import iq.twokeyok.orchestrator.signing.gosign.DeferredPdfSignature;
import iq.twokeyok.orchestrator.signing.gosign.TokenSignatureSource;
import iq.twokeyok.orchestrator.signing.gosign.TokenSigningSessionStore;
import iq.twokeyok.orchestrator.signing.timestamp.DocumentTimestamper;
import iq.twokeyok.orchestrator.web.dto.SignatureAppearanceRequest;

/**
 * Signing with a key on the signer's own token, in the two halves the hardware
 * forces.
 *
 * <p>A USB token is attached to the signer's machine, not to this one, so the
 * orchestrator cannot drive it. {@link #prepare} does everything that can be
 * done on the server - creates the signature field, reserves its
 * {@code /Contents}, computes the digest of what the signature will cover, and
 * registers that digest with Go>Sign - then hands back the snippet the signer's
 * browser runs. {@link #complete} collects the signature the token produced and
 * puts it into the document that was prepared.</p>
 *
 * <p>The document never leaves this host. Go>Sign is given a blank stub to open
 * its transaction and the digest to sign; the prepared document waits in
 * {@link TokenSigningSessionStore} and is only ever returned once a signature
 * over it has verified.</p>
 */
@Service
public class TokenSigningService {

    private static final Logger log = LoggerFactory.getLogger(TokenSigningService.class);

    private final SigningProperties properties;
    private final SignerResolver signerResolver;
    private final AppearanceService appearanceService;
    private final TokenSignatureSource signatureSource;
    private final TokenSigningSessionStore sessions;
    private final DocumentTimestamper documentTimestamper;
    private final AuditLogger audit;
    private final ObjectMapper objectMapper;

    public TokenSigningService(SigningProperties properties,
                               SignerResolver signerResolver,
                               AppearanceService appearanceService,
                               TokenSignatureSource signatureSource,
                               TokenSigningSessionStore sessions,
                               DocumentTimestamper documentTimestamper,
                               AuditLogger audit,
                               ObjectMapper objectMapper) {
        this.properties = properties;
        this.signerResolver = signerResolver;
        this.appearanceService = appearanceService;
        this.signatureSource = signatureSource;
        this.sessions = sessions;
        this.documentTimestamper = documentTimestamper;
        this.audit = audit;
        this.objectMapper = objectMapper;
    }

    /**
     * What the caller needs to get the token to sign.
     *
     * @param sessionId     names the prepared document on the second call
     * @param snippet       the HTML Go>Sign returned, to be rendered by the page
     *                      holding the token
     * @param transactionId the Go>Sign transaction, for correlation
     * @param fieldName     the signature field the signature will go into
     * @param digest        hex of what the token is asked to sign, so a caller can
     *                      check it against the document it sent
     */
    public record PreparedSession(String sessionId, String snippet, String transactionId,
                                  String fieldName, String digest, Instant expiresAt) {
    }

    public PreparedSession prepare(AuthenticatedCaller caller, MultipartFile inputFile, String signerId,
                                   String signatureAppearance) {
        String requestId = UUID.randomUUID().toString();
        if (!signatureSource.isEnabled()) {
            throw new OrchestratorException(ErrorCode.TOKEN_SIGNING_NOT_CONFIGURED);
        }
        byte[] pdf = read(inputFile);
        requirePdf(pdf);

        EffectiveSignerConfig config = signerResolver.resolve(caller, signerId, null);
        if (config.type() != SignerType.TOKEN) {
            throw new OrchestratorException(ErrorCode.SIGNER_NOT_ALLOWED,
                    caller.clientId(), config.signerId() + " (not a TOKEN signer)");
        }
        String fieldName = SignatureFieldNames.choose(config.signatureFieldName(),
                List.of(new SignJob.SignDocument(fileNameOf(inputFile), "application/pdf", pdf)));

        ResolvedAppearance appearance = appearanceService.resolve(
                config.appearanceTemplate(),
                parseAppearance(signatureAppearance),
                config.textDefaults(),
                config.allowRequestAppearance(),
                config.allowRequestAppearanceTemplate());

        SigningProperties.GoSign goSign = properties.gosign();
        // The field is created first, at the template's box, so the signature
        // lands where the appearance says rather than wherever Go>Sign would put
        // one. Appended as an incremental update, which is what lets an
        // already-signed document take another signature.
        byte[] withField = appendField(pdf, fieldName, appearance);
        DeferredPdfSignature.Prepared prepared = DeferredPdfSignature.prepare(
                withField, fieldName, subFilterFor(config), goSign.hashAlgorithm(),
                goSign.signatureSize(),
                new DeferredPdfSignature.SignatureMetadata(appearance.signedBy(), appearance.reason(),
                        appearance.location(), appearance.contactInfo()));

        TokenSignatureSource.Handle handle = signatureSource.open(prepared.digest(), requestId);
        TokenSigningSessionStore.Session session = sessions.open(requestId, caller.clientId(),
                config.signerId(), fileNameOf(inputFile), config, prepared, handle);

        log.info("[{}] Token signing prepared for [{}]: field {}, {} digest, session {}",
                requestId, config.signerId(), fieldName, prepared.digestName(), session.id());
        return new PreparedSession(session.id(), handle.snippet(), handle.transactionId(),
                fieldName, hex(prepared.digest()), session.expiresAt());
    }

    /**
     * Collects the signature and returns the signed document.
     *
     * <p>Nothing is reported as signed until the signature has verified over the
     * prepared bytes. A token that has not signed yet leaves the session intact
     * so the caller can retry; anything else closes it, because a prepared
     * document whose digest Go>Sign already holds cannot be offered twice.</p>
     */
    public SignedDocument complete(AuthenticatedCaller caller, String sessionId) {
        TokenSigningSessionStore.Session session = sessions.claim(sessionId, caller.clientId());
        long startedAt = System.currentTimeMillis();
        String requestId = session.requestId();
        try {
            byte[] cms = signatureSource.fetchCms(session.handle(), requestId);
            byte[] signed = DeferredPdfSignature.inject(session.prepared(), cms);

            // The later steps only append revisions, so the signature's own
            // bytes must still be there untouched when they are done.
            byte[] finished = addLongTermData(signed, requestId);
            if (!startsWith(finished, signed)) {
                throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                        "the validation data rewrote the signed bytes");
            }

            audit.signed(requestId, caller, session.config(), 1, session.handle().documentId(),
                    System.currentTimeMillis() - startedAt);
            sessions.close(session);
            log.info("[{}] Token signature verified and injected; {} bytes returned", requestId, finished.length);
            return new SignedDocument(session.fileName(), finished);
        } catch (OrchestratorException e) {
            if (e.errorCode() == ErrorCode.TOKEN_SESSION_PENDING) {
                // Not a failure: the signer has not finished at the token yet.
                sessions.release(session);
            } else {
                sessions.close(session);
                log.warn("[{}] Token signing failed: {} {}", requestId, e.errorCode().code(), e.getMessage());
            }
            throw e;
        }
    }

    /** @param content the signed document, named as the caller sent it */
    public record SignedDocument(String fileName, byte[] content) {
    }

    /**
     * The same {@code /DSS} and document timestamp a server-side signature gets.
     * A token signature needs it more, not less: the certificate came off a
     * token this host never sees again, so its revocation data has to be
     * captured now.
     */
    private byte[] addLongTermData(byte[] signed, String requestId) {
        List<SignJob.SignResult.SignedDocument> one =
                List.of(new SignJob.SignResult.SignedDocument("signed.pdf", signed));
        List<SignJob.SignResult.SignedDocument> result = documentTimestamper.isEnabled()
                ? documentTimestamper.timestampAll(one, requestId)
                : documentTimestamper.addValidationDataAll(one, requestId);
        return result.get(0).content();
    }

    private byte[] appendField(byte[] pdf, String fieldName, ResolvedAppearance appearance) {
        try {
            return EmptySignatureField.append(pdf, fieldName, appearance.box());
        } catch (IOException e) {
            throw new OrchestratorException(ErrorCode.TOKEN_DOCUMENT_TAMPERED,
                    "the signature field could not be created: " + e.getMessage());
        }
    }

    /**
     * Go>Sign profile 007 reports {@code PADES_B_LT}, so the signature is a
     * PAdES one and its {@code /SubFilter} must say so.
     */
    private static String subFilterFor(EffectiveSignerConfig config) {
        String configured = config.subFilter();
        return configured == null || configured.isBlank() ? "ETSI.CAdES.detached" : configured.trim();
    }

    private static boolean startsWith(byte[] whole, byte[] prefix) {
        return whole.length >= prefix.length
                && Arrays.equals(whole, 0, prefix.length, prefix, 0, prefix.length);
    }

    private byte[] read(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new OrchestratorException(ErrorCode.UNSUPPORTED_MEDIA);
        }
        if (file.getSize() > properties.limits().maxFileSizeBytes()) {
            throw new OrchestratorException(ErrorCode.UNSUPPORTED_MEDIA);
        }
        try {
            return file.getBytes();
        } catch (IOException e) {
            throw new OrchestratorException(ErrorCode.UNSUPPORTED_MEDIA);
        }
    }

    /** Go>Sign's {@code SET_HASH} mode is PDF-only, as its guide states. */
    private static void requirePdf(byte[] pdf) {
        if (pdf.length < 5 || pdf[0] != '%' || pdf[1] != 'P' || pdf[2] != 'D' || pdf[3] != 'F') {
            throw new OrchestratorException(ErrorCode.UNSUPPORTED_MEDIA);
        }
    }

    private static String fileNameOf(MultipartFile file) {
        String name = file.getOriginalFilename();
        return name == null || name.isBlank() ? "document.pdf" : name;
    }

    private SignatureAppearanceRequest parseAppearance(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, SignatureAppearanceRequest.class);
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.INVALID_APPEARANCE, e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }
}
