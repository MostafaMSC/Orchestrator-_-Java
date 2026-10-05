package iq.twokeyok.orchestrator.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Product configuration, bound from {@code signing.*}.
 *
 * <p>The key names deliberately mirror the deployed Ascertia Orchestrator
 * configuration ({@code signing.gateway.*}, {@code signing.dss.signature.*},
 * {@code signing.ras.*}, …) so an existing, working {@code application.yml} drops
 * in unchanged for the parts this product implements. Spring's relaxed binding
 * accepts the snake_case spelling used there ({@code pdf_profile_id}) as well as
 * kebab-case.</p>
 *
 * <p>What this product adds on top is {@link #signers()} — the per-identity
 * configuration that makes one deployment serve several e-seals and natural
 * persons. Resolution order is
 * {@code signature defaults → client → signer → request}.</p>
 *
 * <p>Keys present in the reference configuration but <em>not</em> implemented
 * here are listed in {@code docs/CONFIGURATION.md}; they are ignored rather than
 * silently half-honoured.</p>
 */
@ConfigurationProperties(prefix = "signing")
public record SigningProperties(
        String description,
        String contact,
        /** Writes the request/response documents to {@link #debugPath()}. Never enable in production. */
        @DefaultValue("false") boolean debugMode,
        String debugPath,
        /** {@code implicit} or {@code client_credentials}; see docs/CONFIGURATION.md. */
        @DefaultValue("implicit") String basicAuthType,
        /** Truststore used for outbound TLS to the ADSS services. */
        String truststorePath,
        String truststorePassword,
        /** What to do when neither the request nor the signer entry names a credential. */
        @DefaultValue("LATEST") CredentialStrategy defaultCredentialStrategy,
        @DefaultValue Gateway gateway,
        @DefaultValue Verification verification,
        @DefaultValue Ras ras,
        @DefaultValue Dss dss,
        @DefaultValue Limits limits,
        @DefaultValue DynamicSigner dynamicSigner,
        Map<String, Signer> signers) {

    public SigningProperties {
        signers = signers == null ? new LinkedHashMap<>() : signers;
    }

    /**
     * Lets a caller name a signer that is not pre-registered in
     * {@link #signers()}: {@code signer_id} becomes the ADSS user id,
     * {@code credential_id} the certificate alias and {@code pin} the credential
     * password, with the profile and policy still coming from configuration.
     *
     * <p>This is how the deployed Ascertia Orchestrator works — identity travels
     * with the request — and it is the only workable model once there are more
     * signers than anyone wants to list in a file. Pre-registered signers in
     * {@link #signers()} still win, which is what pins an organisational e-seal
     * to one certificate.</p>
     */
    public record DynamicSigner(
            @DefaultValue("false") boolean enabled,
            @DefaultValue("NATURAL_PERSON") SignerType type,
            /** Falls back to {@code signing.gateway.pdf_profile_id}. */
            String profileId,
            @DefaultValue("true") boolean requirePin,
            @DefaultValue SigningOverrides overrides) {

        /** The synthetic entry for a signer named only by the request. */
        public Signer asSigner(String signerId) {
            return new Signer(true, type, signerId, profileId,
                    null, null, signerId, null, requirePin, overrides);
        }
    }

    /**
     * How a credential is chosen when the request does not name one.
     *
     * <p>{@code NONE} requires an explicit credential and fails otherwise.
     * {@code LATEST} leaves the choice to the ADSS signing profile, which selects
     * the signer's current certificate.</p>
     */
    public enum CredentialStrategy {
        NONE,
        LATEST
    }

    /** The ADSS Signing Service. {@code hdsi} is the interface used for remote authorised signing. */
    public record Gateway(
            @DefaultValue("http://localhost:8777/adss/signing/hdsi") String url,
            /** ADSS originator id. */
            @DefaultValue("Orchestrator-Signing") String clientId,
            /** Signing profile used for PDF documents. */
            String pdfProfileId,
            /** {@code HTTP} (required for remote authorised signing) or {@code DSS}. */
            @DefaultValue("HTTP") String requestMode,
            @DefaultValue("120000") int timeoutMs,
            @DefaultValue("1") int retries,
            /** Forced TLS protocol, e.g. {@code TLSv1.2}. */
            String tlsProtocol,
            @DefaultValue Proxy proxy,
            @DefaultValue StatusPolling statusPolling) {
    }

    /** The ADSS Verification Service, used when a signature is upgraded to LT/LTA. */
    public record Verification(
            String url,
            String clientId,
            String profileId,
            /** 1=XML, 2=DSS, 3=HTTP, as in the reference configuration. */
            @DefaultValue("2") int requestMode) {
    }

    /**
     * The Remote Authorisation Service. Used for the natural-person flow; the
     * keystore is the client certificate RAS requires for mutual TLS.
     */
    public record Ras(
            String url,
            String clientId,
            String clientSecret,
            String profileId,
            String deviceId,
            @DefaultValue("PKCS12") String keystoreType,
            String keystorePath,
            String keystorePassword) {

        public boolean hasClientCredentials() {
            return keystorePath != null && !keystorePath.isBlank();
        }
    }

    public record Dss(@DefaultValue Signature signature, @DefaultValue Tsa tsa, @DefaultValue Ocsp ocsp) {
    }

    /** Signature defaults — the lowest layer of the precedence chain. */
    public record Signature(
            /**
             * Ask ADSS to return the document hash alongside the signature
             * ({@code setSignatureHash}). It does not move any hashing work to
             * this process; {@link #localHash()} is the switch that does.
             *
             * <p>Not the same switch as {@code compute_hash} in the Ascertia
             * Orchestrator's configuration, which signs PDFs with the EU DSS
             * library and means "hash at document signing time" there.</p>
             */
            @DefaultValue("true") boolean computeHash,
            /**
             * Hash the PDF in this process and send only the digest
             * ({@code setLocalHash}). Use when documents must not leave the
             * business network.
             *
             * <p>Requires the document to <em>already contain</em> the empty
             * signature field named by {@link #signatureFieldName()}. The SDK hashes
             * the byte range around that field and throws
             * {@code The signature field '…' does not exist} when it is absent, before
             * any request is sent. Leave it {@code false} to let ADSS create the
             * field and hash the document server side, which is what an ADSS signing
             * profile carrying its own appearance expects.</p>
             */
            @DefaultValue("false") boolean localHash,
            @DefaultValue("SHA256") String hashAlgorithm,
            @DefaultValue("12000") int dictionarySize,
            /**
             * ETSI level in the spelling used by the reference configuration, e.g.
             * {@code PAdES_BASELINE_LTA}. Mapped onto the SDK's PAdES types by
             * {@code PadesLevel}.
             */
            @DefaultValue("PAdES_BASELINE_B") String signatureLevel,
            @DefaultValue("Signature1") String signatureFieldName,
            @DefaultValue("1") int signingPage,
            @DefaultValue("NONE") String containerType,
            @DefaultValue("Please authorise this signing transaction") String dataToBeDisplayed,
            @DefaultValue Appearance appearance) {
    }

    /** The signature appearance catalogue, in the shape of the reference configuration. */
    public record Appearance(
            @DefaultValue("true") boolean enabled,
            /** Fall back to the first enabled template when a request names none. */
            @DefaultValue("true") boolean useDefault,
            /**
             * Name of an appearance defined <em>inside ADSS</em>, e.g.
             * {@code default_sig_appearance}. When set, the orchestrator sends that
             * name instead of an inline appearance document and lets the signing
             * service render it — which is what an ADSS profile configured with its
             * own appearances expects. Inline templates below are then unused for
             * drawing, though their text values still populate the signature.
             */
            String serverSideId,
            /** Optional directory of JSON templates, merged with the ones defined here. */
            String storePath,
            @DefaultValue("false") boolean reloadAlways,
            List<AppearanceTemplateConfig> appearances) {

        /** {@code true} when ADSS owns the appearance and we only name it. */
        public boolean useServerSide() {
            return serverSideId != null && !serverSideId.isBlank();
        }

        public Appearance {
            appearances = appearances == null ? new ArrayList<>() : appearances;
        }
    }

    /**
     * One appearance template. Field names match the {@code signature_appearance}
     * JSON of the API guide, so what is configured and what a caller may send are
     * the same vocabulary.
     */
    public record AppearanceTemplateConfig(
            String templateId,
            String name,
            String description,
            @DefaultValue("true") boolean enabled,
            /** Text placement relative to the signature image: TOP, BOTTOM, LEFT, RIGHT. */
            @DefaultValue("BOTTOM") String signatureTextPosition,
            TextField signedBy,
            TextField signerRole,
            /** {@code value} is a date pattern, e.g. {@code yyyy.MM.dd HH:mm:ss ZZ}. */
            TextField signingDate,
            TextField reason,
            TextField location,
            TextField contactInfo,
            Font textFont,
            Color textBackgroundColor,
            SignatureField signatureField,
            /** {@code value} is a file path, resolved against the config directory. */
            Image companyLogo,
            Image handSignature) {
    }

    public record TextField(@DefaultValue("false") boolean includeLabel, String label, String value) {
    }

    public record Font(@DefaultValue("Helvetica") String name, @DefaultValue("10") int size, Color color) {
    }

    /** RGB 0-255 with an optional alpha in 0.0-1.0. */
    public record Color(@DefaultValue("0") int r,
                        @DefaultValue("0") int g,
                        @DefaultValue("0") int b,
                        @DefaultValue("1.0") double a) {
    }

    /** Signature box on the page, in PDF points from the bottom-left. */
    public record SignatureField(String fieldId,
                                 @DefaultValue("1") int pageNo,
                                 @DefaultValue("0") int x,
                                 @DefaultValue("0") int y,
                                 @DefaultValue("0") int width,
                                 @DefaultValue("0") int height) {

        public boolean placed() {
            return width > 0 && height > 0;
        }
    }

    /** An image given either as a file path (configuration) or Base64 (request). */
    public record Image(String value, String name) {
    }

    public record Tsa(String url, String policyId) {
    }

    public record Ocsp(String url, @DefaultValue("SHA1") String hashAlgorithm) {
    }

    public record Proxy(String host, @DefaultValue("0") int port, String username, String password) {

        public boolean enabled() {
            return host != null && !host.isBlank() && port > 0;
        }
    }

    /** How long a natural person has to approve before the request is abandoned. */
    public record StatusPolling(@DefaultValue("3000") long intervalMs,
                                @DefaultValue("60") int maxAttempts) {

        public long budgetMs() {
            return intervalMs * maxAttempts;
        }
    }

    /** Request guard rails, enforced before anything reaches ADSS. */
    public record Limits(@DefaultValue("20") int maxFilesPerRequest,
                         @DefaultValue("26214400") long maxFileSizeBytes,
                         @DefaultValue("104857600") long maxTotalRequestBytes,
                         @DefaultValue("8") int maxConcurrentSigningRequests) {
    }

    /**
     * A signing identity. {@code ESEAL} is an organisational seal applied
     * unattended; {@code NATURAL_PERSON} is a remote authorised signature the
     * human approves on their device.
     */
    public record Signer(
            @DefaultValue("true") boolean enabled,
            @DefaultValue("ESEAL") SignerType type,
            String displayName,
            /** ADSS signing profile; falls back to {@code signing.gateway.pdf_profile_id}. */
            String profileId,
            /** ADSS certificate alias (e-seal). */
            String certificateAlias,
            /** CSC credential id (natural person); used as the alias when no alias is set. */
            String credentialId,
            /** ADSS/RAS user id. Defaults to the signer key. */
            String userId,
            /** Static credential password for an unattended e-seal only. */
            String credentialPassword,
            /** Reject a natural-person request that arrives without a PIN. */
            @DefaultValue("true") boolean requirePin,
            @DefaultValue SigningOverrides overrides) {
    }

    public enum SignerType {
        ESEAL,
        NATURAL_PERSON
    }

    /**
     * Everything a client or a signer may override, plus the switches deciding how
     * much of it the request itself may change. An unset key means "inherit".
     */
    public record SigningOverrides(
            String hashAlgorithm,
            String signatureLevel,
            Integer dictionarySize,
            String signatureFieldName,
            Integer signingPage,
            Boolean localHash,
            Boolean computeHash,
            String appearanceTemplate,
            String containerType,
            String dataToBeDisplayed,
            String signedBy,
            String signerRole,
            String signingReason,
            String signingLocation,
            String contactInfo,
            Boolean allowRequestAppearance,
            Boolean allowRequestAppearanceTemplate,
            Boolean allowRequestContainerType) {
    }
}
