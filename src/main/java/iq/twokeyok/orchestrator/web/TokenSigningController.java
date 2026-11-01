package iq.twokeyok.orchestrator.web;

import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import iq.twokeyok.orchestrator.security.CallerContext;
import iq.twokeyok.orchestrator.service.TokenSigningService;
import iq.twokeyok.orchestrator.service.TokenSigningService.PreparedSession;
import iq.twokeyok.orchestrator.service.TokenSigningService.SignedDocument;

/**
 * {@code POST /orchestrator/service/sign/token/{prepare,complete}} - signing
 * with a key on the signer's own token.
 *
 * <p>Two calls rather than one, because the token is on the signer's machine:
 * {@code prepare} returns the Go>Sign snippet for the signer's browser to run,
 * and {@code complete} returns the signed document once the token has signed.
 * The document stays on the orchestrator in between - only its hash is given to
 * Go>Sign - so the second call needs nothing but the session id.</p>
 */
@RestController
@RequestMapping("/service/sign/token")
public class TokenSigningController {

    private final TokenSigningService tokenSigning;

    public TokenSigningController(TokenSigningService tokenSigning) {
        this.tokenSigning = tokenSigning;
    }

    /**
     * @return {@code session_id}, the {@code snippet} to render, and the digest
     *         the token is being asked to sign
     */
    @PostMapping(path = "/prepare",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PrepareResponse> prepare(
            HttpServletRequest httpRequest,
            @RequestParam("input_file") MultipartFile inputFile,
            @RequestParam(value = "signer_id", required = false) String signerId,
            @RequestParam(value = "signature_appearance", required = false) String signatureAppearance) {

        PreparedSession prepared = tokenSigning.prepare(
                CallerContext.require(httpRequest), inputFile, signerId, signatureAppearance);
        return ResponseEntity.ok(new PrepareResponse(prepared.sessionId(), prepared.transactionId(),
                prepared.fieldName(), prepared.digest(), prepared.expiresAt().toString(), prepared.snippet()));
    }

    /**
     * @param sessionId the {@code session_id} from {@code prepare}
     * @return the signed PDF; {@code 1135} while the token has not signed yet,
     *         which the caller may retry
     */
    @PostMapping(path = "/complete",
            produces = {MediaType.APPLICATION_PDF_VALUE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<byte[]> complete(
            HttpServletRequest httpRequest,
            @RequestParam("session_id") String sessionId) {

        SignedDocument signed = tokenSigning.complete(CallerContext.require(httpRequest), sessionId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentLength(signed.content().length);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(signed.fileName(), StandardCharsets.UTF_8)
                .build());
        return new ResponseEntity<>(signed.content(), headers, HttpStatus.OK);
    }

    /**
     * @param snippet the HTML Go>Sign returned; it has to be rendered in the page
     *                holding the token, which is the only place it means anything
     */
    public record PrepareResponse(String session_id, String transaction_id, String field_name,
                                  String digest, String expires_at, String snippet) {
    }
}
