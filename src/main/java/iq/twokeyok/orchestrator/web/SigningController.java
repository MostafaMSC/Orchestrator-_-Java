package iq.twokeyok.orchestrator.web;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import iq.twokeyok.orchestrator.security.CallerContext;
import iq.twokeyok.orchestrator.service.SigningOrchestrationService;
import iq.twokeyok.orchestrator.service.SigningOrchestrationService.SignCommand;
import iq.twokeyok.orchestrator.signing.ContainerPackager;

/**
 * {@code POST /orchestrator/service/sign} — Signing PDF (PAdES).
 *
 * <p>The parameter names, the {@code multipart/form-data} content type and the
 * response body follow the TwoKeyOk MiddleWare API guide: a single input file
 * comes back as the signed PDF, several input files come back as an archive.</p>
 */
@RestController
@RequestMapping("/service")
public class SigningController {

    private final SigningOrchestrationService signingService;

    public SigningController(SigningOrchestrationService signingService) {
        this.signingService = signingService;
    }

    @PostMapping(path = "/sign",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = {MediaType.APPLICATION_PDF_VALUE, MediaType.APPLICATION_OCTET_STREAM_VALUE,
                    MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<byte[]> sign(
            HttpServletRequest httpRequest,
            @RequestParam("input_files") List<MultipartFile> inputFiles,
            @RequestParam(value = "signer_id", required = false) String signerId,
            @RequestParam(value = "pin", required = false) String pin,
            @RequestParam(value = "credential_id", required = false) String credentialId,
            @RequestParam(value = "hashes", required = false) String hashes,
            @RequestParam(value = "hash_algo", required = false) String hashAlgo,
            @RequestParam(value = "compute_hash", required = false) String computeHash,
            @RequestParam(value = "container_type", required = false) String containerType,
            @RequestParam(value = "signature_appearance", required = false) String signatureAppearance) {

        SignCommand command = new SignCommand(inputFiles, signerId, pin, credentialId,
                hashes, hashAlgo, computeHash, containerType, signatureAppearance);

        ContainerPackager.Payload payload =
                signingService.sign(CallerContext.require(httpRequest), command);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(payload.contentType()));
        headers.setContentLength(payload.content().length);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(payload.fileName(), java.nio.charset.StandardCharsets.UTF_8)
                .build());
        return new ResponseEntity<>(payload.content(), headers, org.springframework.http.HttpStatus.OK);
    }
}
