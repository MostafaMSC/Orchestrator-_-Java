package iq.twokeyok.orchestrator.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Semaphore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import iq.twokeyok.orchestrator.appearance.AppearanceService;
import iq.twokeyok.orchestrator.appearance.ResolvedAppearance;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.signing.ContainerPackager;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;
import iq.twokeyok.orchestrator.signing.SignJob;
import iq.twokeyok.orchestrator.signing.SignJob.SignDocument;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult;
import iq.twokeyok.orchestrator.signing.SignerResolver;
import iq.twokeyok.orchestrator.signing.SigningBackend;
import iq.twokeyok.orchestrator.web.dto.SignatureAppearanceRequest;

/**
 * The {@code POST /orchestrator/service/sign} workflow: validate, resolve who
 * signs and how, build the visible signature, hand the job to the signing
 * backend, and package what comes back.
 */
@Service
public class SigningOrchestrationService {

    private static final Logger log = LoggerFactory.getLogger(SigningOrchestrationService.class);

    private static final byte[] PDF_MAGIC = "%PDF".getBytes(StandardCharsets.US_ASCII);
    /**
     * Hash algorithms accepted in {@code hash_algo}, taken from the constants the
     * ADSS Client SDK declares on {@code PdfSigningRequest}. The value is passed
     * through verbatim, so anything outside this set is rejected rather than sent
     * to ADSS to fail there.
     */
    private static final Set<String> SUPPORTED_HASH_ALGORITHMS =
            Set.of("SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
                    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512");

    private final SigningProperties properties;
    private final SignerResolver signerResolver;
    private final AppearanceService appearanceService;
    private final SigningBackend signingBackend;
    private final ContainerPackager packager;
    private final AuditLogger audit;
    private final ObjectMapper objectMapper;
    private final Semaphore concurrency;

    public SigningOrchestrationService(SigningProperties properties,
                                       SignerResolver signerResolver,
                                       AppearanceService appearanceService,
                                       SigningBackend signingBackend,
                                       ContainerPackager packager,
                                       AuditLogger audit,
                                       ObjectMapper objectMapper) {
        this.properties = properties;
        this.signerResolver = signerResolver;
        this.appearanceService = appearanceService;
        this.signingBackend = signingBackend;
        this.packager = packager;
        this.audit = audit;
        this.objectMapper = objectMapper;
        this.concurrency = new Semaphore(Math.max(1, properties.limits().maxConcurrentSigningRequests()), true);
    }

    /**
     * @param caller           the authenticated caller
     * @param command          the form parameters of the request
     * @return the payload to stream back to the caller
     */
    public ContainerPackager.Payload sign(AuthenticatedCaller caller, SignCommand command) {
        String requestId = UUID.randomUUID().toString();
        long startedAt = System.currentTimeMillis();

        rejectUnsupportedInputs(command);
        List<SignDocument> documents = readDocuments(command.inputFiles());

        EffectiveSignerConfig config = signerResolver.resolve(
                caller, command.signerId(), command.credentialId());
        config = applyRequestOverrides(config, command);

        ResolvedAppearance appearance = appearanceService.resolve(
                config.appearanceTemplate(),
                parseAppearance(command.signatureAppearance()),
                config.textDefaults(),
                config.allowRequestAppearance(),
                config.allowRequestAppearanceTemplate());

        SignJob job = new SignJob(requestId, config, appearance, documents);

        if (!concurrency.tryAcquire()) {
            throw new OrchestratorException(ErrorCode.SERVICE_BUSY);
        }
        try {
            SignResult result = signingBackend.signPades(job);
            ContainerPackager.Payload payload = packager.pack(result.documents(), config.containerType());
            audit.signed(requestId, caller, config, documents.size(), result.transactionId(),
                    System.currentTimeMillis() - startedAt);
            return payload;
        } catch (OrchestratorException e) {
            audit.failed(requestId, caller, config, e.errorCode(), e.description());
            throw e;
        } finally {
            concurrency.release();
        }
    }

    // ------------------------------------------------------------------
    // Input handling
    // ------------------------------------------------------------------

    /**
     * {@code hashes} / {@code compute_hash} describe signing a digest the caller
     * computed. That path is deliberately not enabled here; rejecting it is safer
     * than silently signing the uploaded document instead.
     */
    private static void rejectUnsupportedInputs(SignCommand command) {
        boolean hasFiles = command.inputFiles() != null && !command.inputFiles().isEmpty();
        boolean hasHashes = command.hashes() != null && !command.hashes().isBlank();
        if (hasHashes) {
            throw new OrchestratorException(ErrorCode.HASH_INPUT_NOT_SUPPORTED);
        }
        if (!hasFiles) {
            throw new OrchestratorException(ErrorCode.NO_FILE_OR_HASH);
        }
    }

    private List<SignDocument> readDocuments(List<MultipartFile> files) {
        SigningProperties.Limits limits = properties.limits();
        if (files.size() > limits.maxFilesPerRequest()) {
            throw new OrchestratorException(ErrorCode.TOO_MANY_FILES);
        }
        long total = 0;
        List<SignDocument> documents = new ArrayList<>(files.size());
        for (MultipartFile file : files) {
            if (file.isEmpty()) {
                throw new OrchestratorException(ErrorCode.NO_FILE_OR_HASH);
            }
            if (file.getSize() > limits.maxFileSizeBytes()) {
                throw new OrchestratorException(ErrorCode.FILE_TOO_LARGE);
            }
            total += file.getSize();
            if (total > limits.maxTotalRequestBytes()) {
                throw new OrchestratorException(ErrorCode.FILE_TOO_LARGE);
            }
            byte[] content;
            try {
                content = file.getBytes();
            } catch (IOException e) {
                throw new OrchestratorException(ErrorCode.INVALID_DOCUMENT, e);
            }
            requirePdf(content);
            documents.add(new SignDocument(
                    safeFileName(file.getOriginalFilename(), documents.size() + 1),
                    file.getContentType(),
                    content));
        }
        return documents;
    }

    /** This endpoint produces PAdES signatures, so the input has to be a PDF. */
    private static void requirePdf(byte[] content) {
        if (content.length < PDF_MAGIC.length) {
            throw new OrchestratorException(ErrorCode.INVALID_DOCUMENT);
        }
        for (int i = 0; i < PDF_MAGIC.length; i++) {
            if (content[i] != PDF_MAGIC[i]) {
                throw new OrchestratorException(ErrorCode.UNSUPPORTED_MEDIA);
            }
        }
    }

    /** Keeps the caller's name but drops any path so it cannot escape a zip entry. */
    private static String safeFileName(String original, int index) {
        if (original == null || original.isBlank()) {
            return "document-" + index + ".pdf";
        }
        String name = original.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        name = name.replaceAll("[\\p{Cntrl}]", "").trim();
        return name.isEmpty() ? "document-" + index + ".pdf" : name;
    }

    private SignatureAppearanceRequest parseAppearance(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, SignatureAppearanceRequest.class);
        } catch (JsonProcessingException e) {
            throw new OrchestratorException(ErrorCode.INVALID_APPEARANCE, e);
        }
    }

    // ------------------------------------------------------------------
    // Request level overrides
    // ------------------------------------------------------------------

    private EffectiveSignerConfig applyRequestOverrides(EffectiveSignerConfig config, SignCommand command) {
        EffectiveSignerConfig result = config;

        if (command.pin() != null && !command.pin().isBlank()) {
            result = result.withCredentialPassword(command.pin());
        } else if (result.isNaturalPerson()
                && (result.credentialPassword() == null || result.credentialPassword().isBlank())
                && requiresPin(result.signerId())) {
            throw new OrchestratorException(ErrorCode.PIN_REQUIRED, result.signerId());
        }

        if (command.containerType() != null && !command.containerType().isBlank()) {
            String requested = command.containerType().trim();
            // Only a *change* needs permission. A request repeating the container
            // already in force is a no-op, and the documented curl example sends
            // container_type=NONE explicitly — refusing that would reject callers
            // who are following the API guide verbatim.
            boolean changesAnything = !requested.equalsIgnoreCase(
                    result.containerType() == null ? "" : result.containerType().trim());
            if (changesAnything && !result.allowRequestContainerType()) {
                throw new OrchestratorException(ErrorCode.CONTAINER_NOT_ALLOWED);
            }
            result = result.withContainerType(requested);
        }

        if (command.hashAlgo() != null && !command.hashAlgo().isBlank()) {
            String algorithm = normaliseHashAlgorithm(command.hashAlgo());
            if (!SUPPORTED_HASH_ALGORITHMS.contains(algorithm)) {
                throw new OrchestratorException(ErrorCode.UNSUPPORTED_HASH_ALGORITHM, command.hashAlgo());
            }
            log.debug("Request overrides the hash algorithm with {}", algorithm);
            result = result.withHashAlgorithm(algorithm);
        }
        return result;
    }

    /**
     * Accepts {@code SHA-256}, {@code sha256} and {@code SHA3-256} alike, and
     * returns the exact spelling the SDK constants use.
     */
    private static String normaliseHashAlgorithm(String requested) {
        String compact = requested.trim().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
        if (compact.startsWith("SHA3") && compact.length() > 4) {
            return "SHA3-" + compact.substring(4);
        }
        return compact;
    }

    private boolean requiresPin(String signerId) {
        SigningProperties.Signer signer = properties.signers().get(signerId);
        return signer == null || signer.requirePin();
    }

    /**
     * The form parameters of {@code POST /service/sign}, named exactly as the
     * TwoKeyOk MiddleWare guide documents them.
     */
    public record SignCommand(List<MultipartFile> inputFiles,
                              String signerId,
                              String pin,
                              String credentialId,
                              String hashes,
                              String hashAlgo,
                              String computeHash,
                              String containerType,
                              String signatureAppearance) {
    }
}
