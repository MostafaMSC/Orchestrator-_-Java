package iq.twokeyok.orchestrator.error;

/** Any failure that has a well-defined {@link ErrorCode} for the caller. */
public class OrchestratorException extends RuntimeException {

    private final ErrorCode errorCode;
    private final String description;

    public OrchestratorException(ErrorCode errorCode, Object... args) {
        this(errorCode, null, args);
    }

    public OrchestratorException(ErrorCode errorCode, Throwable cause, Object... args) {
        super(errorCode.message(args), cause);
        this.errorCode = errorCode;
        this.description = errorCode.message(args);
    }

    public ErrorCode errorCode() {
        return errorCode;
    }

    public String description() {
        return description;
    }
}
