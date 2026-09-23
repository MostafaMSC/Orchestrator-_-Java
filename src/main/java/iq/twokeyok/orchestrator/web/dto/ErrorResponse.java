package iq.twokeyok.orchestrator.web.dto;

/**
 * The error body of the TwoKeyOk MiddleWare surface:
 * {@code {"error_code": 1002, "error_description": "…"}}.
 */
public record ErrorResponse(int errorCode, String errorDescription) {
}
