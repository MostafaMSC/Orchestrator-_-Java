package iq.twokeyok.orchestrator.signing;

import iq.twokeyok.orchestrator.appearance.AppearanceService.TextDefaults;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;

/**
 * Everything the signing backend needs for one request, after the
 * {@code defaults → client → signer → request} chain has been applied.
 *
 * @param signerId           the identity the signature is created for
 * @param type               e-seal (unattended) or natural person (remote authorised)
 * @param adssClientId       originator id sent to ADSS
 * @param profileId          ADSS signing profile
 * @param certificateAlias   certificate alias / credential id, or {@code null} to
 *                           let the ADSS profile choose (credential strategy LATEST)
 * @param userId             ADSS-RAS user id; {@code null} for an e-seal
 * @param credentialPassword signer PIN, or the e-seal's static credential password
 * @param hashAlgorithm      digest algorithm, e.g. {@code SHA384}
 * @param padesSignatureType SDK PAdES type, or {@code null} when the signing
 *                           profile determines the level
 * @param signatureDictionarySize reserved space for the signature dictionary
 * @param signatureFieldName name of the PDF signature field
 * @param signingPage        page the visible signature goes on
 * @param localHash          hash in the orchestrator instead of at ADSS
 * @param computeHash        ask ADSS to compute the final hash at signing time
 * @param appearanceTemplate appearance template id, or {@code null} for the default
 * @param containerType      output container
 * @param dataToBeDisplayed  text shown on the signer's authorisation device
 * @param textDefaults       fixed appearance text values
 * @param allowRequestAppearance         may the request change appearance values?
 * @param allowRequestAppearanceTemplate may the request pick another template?
 * @param allowRequestContainerType      may the request choose the container?
 */
public record EffectiveSignerConfig(
        String signerId,
        SignerType type,
        String adssClientId,
        String profileId,
        String certificateAlias,
        String userId,
        String credentialPassword,
        String hashAlgorithm,
        String padesSignatureType,
        int signatureDictionarySize,
        String signatureFieldName,
        int signingPage,
        boolean localHash,
        boolean computeHash,
        String appearanceTemplate,
        String containerType,
        String dataToBeDisplayed,
        TextDefaults textDefaults,
        boolean allowRequestAppearance,
        boolean allowRequestAppearanceTemplate,
        boolean allowRequestContainerType) {

    public boolean isNaturalPerson() {
        return type == SignerType.NATURAL_PERSON;
    }

    public EffectiveSignerConfig withCredentialPassword(String pin) {
        return new EffectiveSignerConfig(signerId, type, adssClientId, profileId, certificateAlias, userId,
                pin, hashAlgorithm, padesSignatureType, signatureDictionarySize, signatureFieldName, signingPage,
                localHash, computeHash, appearanceTemplate, containerType, dataToBeDisplayed, textDefaults,
                allowRequestAppearance, allowRequestAppearanceTemplate, allowRequestContainerType);
    }

    public EffectiveSignerConfig withHashAlgorithm(String algorithm) {
        return new EffectiveSignerConfig(signerId, type, adssClientId, profileId, certificateAlias, userId,
                credentialPassword, algorithm, padesSignatureType, signatureDictionarySize, signatureFieldName,
                signingPage, localHash, computeHash, appearanceTemplate, containerType, dataToBeDisplayed,
                textDefaults, allowRequestAppearance, allowRequestAppearanceTemplate, allowRequestContainerType);
    }

    public EffectiveSignerConfig withContainerType(String container) {
        return new EffectiveSignerConfig(signerId, type, adssClientId, profileId, certificateAlias, userId,
                credentialPassword, hashAlgorithm, padesSignatureType, signatureDictionarySize, signatureFieldName,
                signingPage, localHash, computeHash, appearanceTemplate, container, dataToBeDisplayed,
                textDefaults, allowRequestAppearance, allowRequestAppearanceTemplate, allowRequestContainerType);
    }
}
