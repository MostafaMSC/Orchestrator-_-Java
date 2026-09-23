package iq.twokeyok.orchestrator.signing;

import java.util.function.Function;

import org.springframework.stereotype.Service;

import iq.twokeyok.orchestrator.appearance.AppearanceService.TextDefaults;
import iq.twokeyok.orchestrator.config.CscProperties.RegisteredClient;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.CredentialStrategy;
import iq.twokeyok.orchestrator.config.SigningProperties.Signature;
import iq.twokeyok.orchestrator.config.SigningProperties.Signer;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.config.SigningProperties.SigningOverrides;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.security.AuthenticatedCaller;
import iq.twokeyok.orchestrator.security.ClientRegistry;

/**
 * Decides which configured identity signs a request and folds the
 * {@code signature defaults → client → signer} chain into one
 * {@link EffectiveSignerConfig}.
 *
 * <p>The signer is authoritative when the caller presented their own access
 * token: a business application cannot sign as somebody else by putting a
 * different {@code signer_id} in the form.</p>
 */
@Service
public class SignerResolver {

    private final SigningProperties properties;
    private final ClientRegistry clientRegistry;

    public SignerResolver(SigningProperties properties, ClientRegistry clientRegistry) {
        this.properties = properties;
        this.clientRegistry = clientRegistry;
    }

    public EffectiveSignerConfig resolve(AuthenticatedCaller caller,
                                         String requestedSignerId,
                                         String requestedCredentialId) {
        RegisteredClient client = clientRegistry.find(caller.clientId()).orElse(null);
        String signerId = chooseSignerId(caller, client, requestedSignerId);

        Signer signer = properties.signers().get(signerId);
        if (signer == null) {
            throw new OrchestratorException(ErrorCode.UNKNOWN_SIGNER, signerId);
        }
        if (!signer.enabled()) {
            throw new OrchestratorException(ErrorCode.SIGNER_DISABLED, signerId);
        }
        if (client != null && !client.allowedSignerIds().isEmpty()
                && !client.allowedSignerIds().contains(signerId)) {
            throw new OrchestratorException(ErrorCode.SIGNER_NOT_ALLOWED, caller.clientId(), signerId);
        }

        String profileId = firstNonBlank(signer.profileId(), properties.gateway().pdfProfileId());
        if (profileId == null) {
            throw new OrchestratorException(ErrorCode.SIGNER_PROFILE_INCOMPLETE, signerId);
        }

        SigningOverrides clientOverrides = client == null ? null : client.overrides();
        SigningOverrides signerOverrides = signer.overrides();
        Signature defaults = properties.dss().signature();

        String credentialAlias = resolveCredentialAlias(signer, signerId,
                caller.credentialId(), requestedCredentialId);

        String signatureLevel = pick(clientOverrides, signerOverrides,
                SigningOverrides::signatureLevel, defaults.signatureLevel());

        return new EffectiveSignerConfig(
                signerId,
                signer.type(),
                clientRegistry.adssClientId(caller.clientId()),
                profileId,
                credentialAlias,
                signer.type() == SignerType.NATURAL_PERSON
                        ? firstNonBlank(signer.userId(), signerId)
                        : null,
                signer.credentialPassword(),
                pick(clientOverrides, signerOverrides, SigningOverrides::hashAlgorithm, defaults.hashAlgorithm()),
                // Configured as an ETSI level; the SDK wants its own PAdES type.
                PadesLevel.toSdkType(signatureLevel),
                pick(clientOverrides, signerOverrides, SigningOverrides::dictionarySize, defaults.dictionarySize()),
                pick(clientOverrides, signerOverrides, SigningOverrides::signatureFieldName, defaults.signatureFieldName()),
                pick(clientOverrides, signerOverrides, SigningOverrides::signingPage, defaults.signingPage()),
                pick(clientOverrides, signerOverrides, SigningOverrides::localHash, defaults.localHash()),
                pick(clientOverrides, signerOverrides, SigningOverrides::computeHash, defaults.computeHash()),
                pick(clientOverrides, signerOverrides, SigningOverrides::appearanceTemplate, null),
                pick(clientOverrides, signerOverrides, SigningOverrides::containerType, defaults.containerType()),
                pick(clientOverrides, signerOverrides, SigningOverrides::dataToBeDisplayed, defaults.dataToBeDisplayed()),
                new TextDefaults(
                        pick(clientOverrides, signerOverrides, SigningOverrides::signedBy, signer.displayName()),
                        pick(clientOverrides, signerOverrides, SigningOverrides::signerRole, null),
                        pick(clientOverrides, signerOverrides, SigningOverrides::signingReason, null),
                        pick(clientOverrides, signerOverrides, SigningOverrides::signingLocation, null),
                        pick(clientOverrides, signerOverrides, SigningOverrides::contactInfo, null)),
                pick(clientOverrides, signerOverrides, SigningOverrides::allowRequestAppearance, true),
                pick(clientOverrides, signerOverrides, SigningOverrides::allowRequestAppearanceTemplate, true),
                pick(clientOverrides, signerOverrides, SigningOverrides::allowRequestContainerType, true));
    }

    private static String chooseSignerId(AuthenticatedCaller caller,
                                         RegisteredClient client,
                                         String requestedSignerId) {
        if (caller.isSigner()) {
            if (requestedSignerId != null && !requestedSignerId.isBlank()
                    && !requestedSignerId.equals(caller.signerId())) {
                throw new OrchestratorException(ErrorCode.SIGNER_NOT_ALLOWED,
                        caller.clientId(), requestedSignerId);
            }
            return caller.signerId();
        }
        if (requestedSignerId != null && !requestedSignerId.isBlank()) {
            return requestedSignerId;
        }
        String fallback = client == null ? null : client.defaultSignerId();
        if (fallback == null || fallback.isBlank()) {
            throw new OrchestratorException(ErrorCode.SIGNER_ID_MISSING);
        }
        return fallback;
    }

    /**
     * A configured credential is authoritative: a request may only supply one when
     * the signer entry leaves it open, and it must match otherwise.
     *
     * <p>When nothing names a credential, {@code default_credential_strategy}
     * decides — {@code NONE} refuses, {@code LATEST} returns {@code null} and lets
     * the ADSS signing profile pick the signer's current certificate.</p>
     */
    private String resolveCredentialAlias(Signer signer,
                                          String signerId,
                                          String tokenCredentialId,
                                          String requestedCredentialId) {
        String configured = firstNonBlank(signer.certificateAlias(), signer.credentialId());
        String supplied = firstNonBlank(requestedCredentialId, tokenCredentialId);

        if (configured != null) {
            if (supplied != null && !supplied.equals(configured)) {
                throw new OrchestratorException(ErrorCode.NO_SIGNER_CERTIFICATE, signerId, supplied);
            }
            return configured;
        }
        if (supplied != null) {
            return supplied;
        }
        if (properties.defaultCredentialStrategy() == CredentialStrategy.NONE) {
            throw new OrchestratorException(ErrorCode.CREDENTIAL_REQUIRED);
        }
        return null;
    }

    private static <T> T pick(SigningOverrides client,
                              SigningOverrides signer,
                              Function<SigningOverrides, T> accessor,
                              T fallback) {
        T value = signer == null ? null : accessor.apply(signer);
        if (value != null) {
            return value;
        }
        value = client == null ? null : accessor.apply(client);
        return value != null ? value : fallback;
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return null;
    }
}
