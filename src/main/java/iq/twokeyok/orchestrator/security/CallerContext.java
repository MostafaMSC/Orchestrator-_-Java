package iq.twokeyok.orchestrator.security;

import jakarta.servlet.http.HttpServletRequest;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;

/**
 * Carries the authenticated caller from {@link CallerAuthenticationFilter} to the
 * controllers as a request attribute, so nothing has to be threaded through the
 * signature of every method and nothing leaks between requests.
 */
public final class CallerContext {

    static final String ATTRIBUTE = CallerContext.class.getName() + ".caller";

    private CallerContext() {
    }

    public static void set(HttpServletRequest request, AuthenticatedCaller caller) {
        request.setAttribute(ATTRIBUTE, caller);
    }

    public static AuthenticatedCaller require(HttpServletRequest request) {
        Object caller = request.getAttribute(ATTRIBUTE);
        if (caller == null) {
            throw new OrchestratorException(ErrorCode.MISSING_AUTHORIZATION);
        }
        return (AuthenticatedCaller) caller;
    }
}
