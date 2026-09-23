package iq.twokeyok.orchestrator.error;

import org.springframework.http.HttpStatus;

/**
 * Error codes returned to business applications.
 *
 * <p>Codes 1001-1034 are the TwoKeyOk MiddleWare codes documented at
 * {@code https://api-middle.twokeyok.iq/errors}; they keep their exact numbers
 * and wording so an integration written against the reference guide keeps
 * working. Codes from 1100 upwards are orchestrator extensions and are listed in
 * {@code docs/API.md}.</p>
 */
public enum ErrorCode {

    // ---- Reference codes -------------------------------------------------
    INTERNAL_ERROR(1001, "Internal server error occurred. Please try again later", HttpStatus.INTERNAL_SERVER_ERROR),
    SIGNER_ID_MISSING(1002, "Invalid request - Required parameter signer_id not provided in request", HttpStatus.BAD_REQUEST),
    FILE_TOO_LARGE(1003, "Request exceeds its maximum permitted file size", HttpStatus.BAD_REQUEST),
    NUM_SIGNATURES_MISMATCH(1004, "Invalid request - numSignatures doesn't match with hashes provided", HttpStatus.BAD_REQUEST),
    INVALID_CLIENT_ID(1005, "Invalid client_id in request", HttpStatus.UNAUTHORIZED),
    INVALID_CLIENT_CREDENTIALS(1009, "Invalid client_id or client_secret", HttpStatus.UNAUTHORIZED),
    INVALID_OR_EXPIRED_TOKEN(1013, "Invalid or expired token", HttpStatus.UNAUTHORIZED),
    RAS_PROFILE_MISCONFIGURED(1025, "RAS Service profile is not configured correctly. Select No Authentication for mobile authorization", HttpStatus.INTERNAL_SERVER_ERROR),
    TOKEN_CLAIM_MISSING(1026, "The access token is missing a required attribute. No claim found: Required-ClaimId: [{0}] -> SignerInfoId: [{1}]", HttpStatus.UNAUTHORIZED),
    SIGNER_NOT_REGISTERED(1027, "One-Time-Signing is disabled in orchestrator. Signer [{0}] is not registered with ADSS Server.", HttpStatus.BAD_REQUEST),
    SIGNER_NOT_CERTIFIED(1028, "One-Time-Signing is disabled in orchestrator. Signer [{0}] is not certified.", HttpStatus.BAD_REQUEST),
    NO_SIGNER_CERTIFICATE(1029, "No signer certificate found. Signer: [{0}] with Credential-ID: [{1}]", HttpStatus.BAD_REQUEST),
    NO_FILE_OR_HASH(1030, "No file or Hash provided in request", HttpStatus.BAD_REQUEST),
    INVALID_PIN(1031, "Invalid Signer PIN provided in request", HttpStatus.UNAUTHORIZED),
    INVALID_DOCUMENT(1034, "Invalid/Corrupted document found in request", HttpStatus.BAD_REQUEST),

    // ---- Orchestrator extensions ----------------------------------------
    TOO_MANY_FILES(1100, "Request exceeds the maximum permitted number of input files", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_MEDIA(1101, "Unsupported input file type for PAdES signing. Only PDF documents are accepted", HttpStatus.BAD_REQUEST),
    UNKNOWN_SIGNER(1102, "Signer [{0}] is not configured in this orchestrator", HttpStatus.BAD_REQUEST),
    SIGNER_DISABLED(1103, "Signer [{0}] is disabled", HttpStatus.FORBIDDEN),
    SIGNER_NOT_ALLOWED(1104, "Client [{0}] is not permitted to sign as [{1}]", HttpStatus.FORBIDDEN),
    PIN_REQUIRED(1105, "Signer [{0}] requires a PIN to authorise the signature", HttpStatus.BAD_REQUEST),
    APPEARANCE_NOT_FOUND(1106, "Signature appearance template [{0}] was not found", HttpStatus.BAD_REQUEST),
    APPEARANCE_NOT_ALLOWED(1107, "This client is not permitted to override the signature appearance", HttpStatus.FORBIDDEN),
    INVALID_APPEARANCE(1108, "The signature_appearance parameter is not valid JSON", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_CONTAINER(1109, "Container type [{0}] is not supported by this orchestrator release", HttpStatus.BAD_REQUEST),
    CONTAINER_NOT_ALLOWED(1110, "This client is not permitted to choose the container type", HttpStatus.FORBIDDEN),
    SIGNER_PROFILE_INCOMPLETE(1111, "Signer [{0}] has no profile-id configured", HttpStatus.INTERNAL_SERVER_ERROR),
    AUTHORISATION_TIMEOUT(1112, "The signer did not authorise the transaction within the configured time", HttpStatus.GATEWAY_TIMEOUT),
    AUTHORISATION_DECLINED(1113, "The signer declined the signing transaction", HttpStatus.FORBIDDEN),
    ADSS_UNAVAILABLE(1114, "The signing service is not reachable", HttpStatus.BAD_GATEWAY),
    ADSS_REJECTED(1115, "The signing service rejected the request: {0}", HttpStatus.BAD_GATEWAY),
    SERVICE_BUSY(1116, "The orchestrator is handling its maximum number of concurrent signing requests", HttpStatus.SERVICE_UNAVAILABLE),
    MISSING_AUTHORIZATION(1117, "Authorization header is missing", HttpStatus.UNAUTHORIZED),
    HASH_INPUT_NOT_SUPPORTED(1118, "Signing pre-computed hashes is not enabled in this orchestrator release. Send the document in input_files", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_HASH_ALGORITHM(1119, "Unsupported hash algorithm [{0}]", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_SIGNATURE_LEVEL(1120, "Signature level [{0}] is not a PDF signature level supported by this orchestrator", HttpStatus.INTERNAL_SERVER_ERROR),
    APPEARANCE_IMAGE_UNREADABLE(1121, "Appearance image [{0}] could not be read", HttpStatus.INTERNAL_SERVER_ERROR),
    CREDENTIAL_REQUIRED(1122, "No credential was supplied and default_credential_strategy is NONE", HttpStatus.BAD_REQUEST);

    private final int code;
    private final String message;
    private final HttpStatus status;

    ErrorCode(int code, String message, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.status = status;
    }

    public int code() {
        return code;
    }

    public HttpStatus status() {
        return status;
    }

    /** Fills the {@code {0}}, {@code {1}} … placeholders of the reference messages. */
    public String message(Object... args) {
        String text = message;
        for (int i = 0; i < args.length; i++) {
            text = text.replace("{" + i + "}", String.valueOf(args[i]));
        }
        return text;
    }
}
