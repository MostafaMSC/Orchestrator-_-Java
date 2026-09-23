package iq.twokeyok.orchestrator.signing.adss;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.ascertia.adss.client.api.signing.PdfSigningRequest;
import com.ascertia.adss.client.api.signing.PdfSigningResponse;
import com.ascertia.adss.client.api.signing.SigningRequest;
import com.ascertia.adss.client.api.signing.StatusRequest;
import com.ascertia.adss.client.api.signing.StatusResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.appearance.ResolvedAppearance;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;
import iq.twokeyok.orchestrator.signing.SignJob;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult.SignedDocument;
import iq.twokeyok.orchestrator.signing.SigningBackend;

/**
 * Drives the ADSS Client SDK for both signing modes.
 *
 * <p>An <strong>e-seal</strong> is a straight profile-and-alias signature: ADSS
 * signs immediately and the response carries the signed PDF.</p>
 *
 * <p>A <strong>natural person</strong> signature is remote authorised: the
 * request also carries the RAS user id and the signer's PIN, ADSS answers
 * {@code PENDING} with a transaction id, the signer approves on their device,
 * and the orchestrator polls {@link StatusRequest} until the signature comes
 * back and is embedded into the document.</p>
 */
@Component
public class AdssSigningBackend implements SigningBackend {

    private static final Logger log = LoggerFactory.getLogger(AdssSigningBackend.class);

    private final SigningProperties properties;

    public AdssSigningBackend(SigningProperties properties) {
        this.properties = properties;
    }

    @Override
    public SignResult signPades(SignJob job) {
        SigningProperties.Gateway gateway = properties.gateway();
        EffectiveSignerConfig config = job.config();
        try {
            PdfSigningRequest request = buildRequest(job);
            log.info("[{}] Sending PAdES request to {}: signer={} type={} profile={} credential={} documents={}",
                    job.requestId(), gateway.url(), config.signerId(), config.type(), config.profileId(),
                    config.certificateAlias() == null ? "<profile default>" : config.certificateAlias(),
                    job.documents().size());

            PdfSigningResponse response = (PdfSigningResponse) request.send(gateway.url());
            if (!response.isSuccessful()) {
                throw new OrchestratorException(ErrorCode.ADSS_REJECTED,
                        describe(response.getErrorCode(), response.getErrorMessage()));
            }

            String transactionId = response.getTransactionID();
            if (transactionId != null && !transactionId.isBlank()) {
                awaitAuthorisation(job, response, transactionId);
            }
            return collect(job, response, transactionId);
        } catch (OrchestratorException e) {
            throw e;
        } catch (java.net.ConnectException | java.net.UnknownHostException | java.net.SocketTimeoutException e) {
            log.error("[{}] ADSS at {} is not reachable: {}", job.requestId(), gateway.url(), e.getMessage());
            throw new OrchestratorException(ErrorCode.ADSS_UNAVAILABLE, e);
        } catch (Exception e) {
            log.error("[{}] PAdES signing failed", job.requestId(), e);
            throw new OrchestratorException(ErrorCode.INTERNAL_ERROR, e);
        }
    }

    // ------------------------------------------------------------------
    // Request construction
    // ------------------------------------------------------------------

    private PdfSigningRequest buildRequest(SignJob job) throws Exception {
        EffectiveSignerConfig config = job.config();
        List<SignJob.SignDocument> documents = job.documents();

        PdfSigningRequest request =
                new PdfSigningRequest(config.adssClientId(), documents.get(0).content());
        for (int i = 1; i < documents.size(); i++) {
            request.addDocument(documents.get(i).content());
        }

        request.setRequestMode(requestMode(properties.gateway().requestMode()));
        request.setProfileId(config.profileId());
        // Left unset under credential strategy LATEST: the ADSS profile then picks
        // the signer's current certificate.
        if (config.certificateAlias() != null && !config.certificateAlias().isBlank()) {
            request.setCertificateAlias(config.certificateAlias());
        }
        request.setLocalHash(config.localHash());
        request.setSignatureHash(config.computeHash());
        request.setHashAlgorithm(config.hashAlgorithm());
        request.setSignatureDictionarySize(config.signatureDictionarySize());
        request.setSigningField(config.signatureFieldName());

        applyIdentity(request, config);
        applyAppearance(request, job.appearance(), config);
        applyLongTerm(request, config);
        applyTransport(request);

        if (documents.size() == 1) {
            request.setDocumentID(job.requestId());
            request.setDocumentName(documents.get(0).fileName());
        }
        if (config.dataToBeDisplayed() != null && !config.dataToBeDisplayed().isBlank()) {
            request.setDataToBeDisplayed(config.dataToBeDisplayed());
        }
        if (properties.debugMode()) {
            request.setHttpVerbose(true);
        }
        return request;
    }

    /**
     * An e-seal signs with the service certificate alone; a natural person adds
     * the RAS user id and the PIN that authorises the key.
     */
    private static void applyIdentity(PdfSigningRequest request, EffectiveSignerConfig config) {
        if (config.isNaturalPerson()) {
            request.setUserID(config.userId());
        }
        if (config.credentialPassword() != null && !config.credentialPassword().isBlank()) {
            request.setCertificatePassword(config.credentialPassword());
        }
    }

    private static void applyAppearance(PdfSigningRequest request,
                                        ResolvedAppearance appearance,
                                        EffectiveSignerConfig config) {
        if (appearance == null) {
            request.setSigningPage(config.signingPage());
            return;
        }
        request.setSignatureAppearance(appearance.appearanceXml());

        setIfPresent(appearance.signedBy(), request::setSignedBy);
        setIfPresent(appearance.reason(), request::setSigningReason);
        setIfPresent(appearance.location(), request::setSigningLocation);
        setIfPresent(appearance.contactInfo(), request::setContactInfo);
        setIfPresent(appearance.signerRole(), request::setSignerRole);

        if (appearance.companyLogo() != null) {
            request.setCompanyLogo(appearance.companyLogo());
        }
        if (appearance.handSignature() != null) {
            request.setHandSignature(appearance.handSignature());
        }

        ResolvedAppearance.SignatureBox box = appearance.box();
        int page = box != null ? box.pageNo() : config.signingPage();
        request.setSigningPage(page);
        if (box != null) {
            // The SDK exposes two mutually exclusive calls: an empty field is
            // created locally when the orchestrator hashes the document itself,
            // otherwise ADSS places the visible signature server side.
            if (config.localHash()) {
                request.addEmptySignatureFieldPosition(box.x(), box.y(), box.x2(), box.y2(),
                        page, config.signatureFieldName());
            } else {
                request.addSignaturePosition(box.x(), box.y(), box.x2(), box.y2(),
                        page, config.signatureFieldName(), null);
            }
        }
    }

    /**
     * PAdES-LT / LTV / B-LTA need revocation data and a timestamp, which ADSS
     * fetches from the configured verification and TSA services.
     */
    private void applyLongTerm(PdfSigningRequest request, EffectiveSignerConfig config) {
        String type = config.padesSignatureType();
        if (type == null || type.isBlank()) {
            return;
        }
        request.setPadesSignatureType(type);

        SigningProperties.Verification verification = properties.verification();
        SigningProperties.Tsa tsa = properties.dss().tsa();
        setIfPresent(verification.url(), request::setVerificationServiceAddress);
        setIfPresent(verification.profileId(), request::setVerificationProfile);
        setIfPresent(tsa.url(), request::setTimeStampServiceAddress);
        setIfPresent(tsa.policyId(), request::setTimeStampPolicyId);

        if (isBlank(verification.url()) || isBlank(tsa.url())) {
            log.warn("Signature level {} needs both signing.verification.url and signing.dss.tsa.url; "
                    + "ADSS will reject the upgrade if either is missing", type);
        }
    }

    /** TLS, proxy and timeout settings shared by the signing and status calls. */
    private void applyTransport(com.ascertia.adss.client.api.Request request) throws Exception {
        SigningProperties.Gateway gateway = properties.gateway();
        request.setTimeout(gateway.timeoutMs());
        request.setRequestRetries(gateway.retries());
        setIfPresent(gateway.tlsProtocol(), request::setDefaultProtocol);

        // RAS supplies the client certificate ADSS expects for mutual TLS.
        SigningProperties.Ras ras = properties.ras();
        if (ras.hasClientCredentials()) {
            request.setSslClientCredentials(ras.keystorePath(), ras.keystorePassword());
        }
        if (!isBlank(properties.truststorePath())) {
            request.setSslTrustStore(properties.truststorePath(), properties.truststorePassword());
        }
        if (gateway.proxy().enabled()) {
            request.setProxy(gateway.proxy().host(), gateway.proxy().port());
        }
    }

    // ------------------------------------------------------------------
    // Remote authorisation
    // ------------------------------------------------------------------

    private void awaitAuthorisation(SignJob job, PdfSigningResponse response, String transactionId)
            throws Exception {
        SigningProperties.StatusPolling polling = properties.gateway().statusPolling();
        log.info("[{}] Waiting for signer {} to authorise transaction {} (up to {} s)",
                job.requestId(), job.config().signerId(), transactionId, polling.budgetMs() / 1000);

        StatusRequest statusRequest = new StatusRequest(job.config().adssClientId(), transactionId);
        statusRequest.setProfileID(job.config().profileId());
        applyTransport(statusRequest);

        for (int attempt = 1; attempt <= polling.maxAttempts(); attempt++) {
            StatusResponse status = (StatusResponse) statusRequest.send(properties.gateway().url());
            String state = status.getStatus() == null ? "" : status.getStatus().toUpperCase(Locale.ROOT);
            switch (state) {
                case "SIGNED", "SUCCESS" -> {
                    response.embedSignatures(status.getSignedDocuments());
                    log.info("[{}] Transaction {} authorised after {} attempt(s)",
                            job.requestId(), transactionId, attempt);
                    return;
                }
                case "DECLINED", "UNAUTHORISED" ->
                        throw new OrchestratorException(ErrorCode.AUTHORISATION_DECLINED);
                case "EXPIRE", "EXPIRED" ->
                        throw new OrchestratorException(ErrorCode.AUTHORISATION_TIMEOUT);
                case "FAILED", "FAIL" -> throw new OrchestratorException(ErrorCode.ADSS_REJECTED,
                        describe(status.getErrorCode(), status.getErrorMessage()));
                default -> log.debug("[{}] Transaction {} status={} ({}/{})",
                        job.requestId(), transactionId, state, attempt, polling.maxAttempts());
            }
            Thread.sleep(polling.intervalMs());
        }
        throw new OrchestratorException(ErrorCode.AUTHORISATION_TIMEOUT);
    }

    // ------------------------------------------------------------------
    // Response handling
    // ------------------------------------------------------------------

    private static SignResult collect(SignJob job, PdfSigningResponse response, String transactionId) {
        List<?> signed = response.getDocuments();
        if (signed == null || signed.isEmpty()) {
            throw new OrchestratorException(ErrorCode.ADSS_REJECTED, "no signed document returned");
        }
        if (signed.size() != job.documents().size()) {
            log.warn("[{}] ADSS returned {} document(s) for {} input(s)",
                    job.requestId(), signed.size(), job.documents().size());
        }
        List<SignedDocument> result = new ArrayList<>(signed.size());
        for (int i = 0; i < signed.size(); i++) {
            String name = i < job.documents().size()
                    ? job.documents().get(i).fileName()
                    : "signed-" + (i + 1) + ".pdf";
            result.add(new SignedDocument(name, (byte[]) signed.get(i)));
        }
        return new SignResult(result, transactionId);
    }

    private static String describe(int errorCode, String errorMessage) {
        String message = errorMessage == null || errorMessage.isBlank() ? "unspecified error" : errorMessage;
        return errorCode == 0 ? message : errorCode + " - " + message;
    }

    private static int requestMode(String mode) {
        return "DSS".equalsIgnoreCase(mode) ? SigningRequest.DSS : SigningRequest.HTTP;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static void setIfPresent(String value, ThrowingSetter setter) {
        if (isBlank(value)) {
            return;
        }
        try {
            setter.accept(value);
        } catch (Exception e) {
            throw new OrchestratorException(ErrorCode.INTERNAL_ERROR, e);
        }
    }

    @FunctionalInterface
    private interface ThrowingSetter {
        void accept(String value) throws Exception;
    }
}
