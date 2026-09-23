package iq.twokeyok.orchestrator.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.web.dto.ErrorResponse;

/**
 * Turns every failure into the documented
 * {@code {"error_code": …, "error_description": …}} body.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(OrchestratorException.class)
    public ResponseEntity<ErrorResponse> handle(OrchestratorException e) {
        if (e.errorCode().status().is5xxServerError()) {
            log.error("Request failed with {}: {}", e.errorCode().code(), e.description(), e);
        } else {
            log.info("Request rejected with {}: {}", e.errorCode().code(), e.description());
        }
        return respond(e.errorCode(), e.description());
    }

    @ExceptionHandler({MissingServletRequestParameterException.class, MissingServletRequestPartException.class})
    public ResponseEntity<ErrorResponse> handleMissingPart(Exception e) {
        String name = e instanceof MissingServletRequestParameterException missing
                ? missing.getParameterName()
                : ((MissingServletRequestPartException) e).getRequestPartName();
        if ("signer_id".equals(name)) {
            return respond(ErrorCode.SIGNER_ID_MISSING, ErrorCode.SIGNER_ID_MISSING.message());
        }
        if ("input_files".equals(name)) {
            return respond(ErrorCode.NO_FILE_OR_HASH, ErrorCode.NO_FILE_OR_HASH.message());
        }
        return respond(ErrorCode.NO_FILE_OR_HASH, "Invalid request - Required parameter " + name + " not provided in request");
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> handleTooLarge(MaxUploadSizeExceededException e) {
        return respond(ErrorCode.FILE_TOO_LARGE, ErrorCode.FILE_TOO_LARGE.message());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        log.error("Unhandled failure", e);
        return respond(ErrorCode.INTERNAL_ERROR, ErrorCode.INTERNAL_ERROR.message());
    }

    private static ResponseEntity<ErrorResponse> respond(ErrorCode code, String description) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new ResponseEntity<>(new ErrorResponse(code.code(), description), headers, code.status());
    }
}
