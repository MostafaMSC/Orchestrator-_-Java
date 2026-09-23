package iq.twokeyok.orchestrator.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.web.dto.ErrorResponse;

/**
 * Accepts the two authorization schemes of the TwoKeyOk MiddleWare surface:
 * {@code Bearer <signer-access-token>} and
 * {@code Basic base64(clientId:clientSecret)}.
 *
 * <p>Actuator endpoints are left alone so a load balancer can probe the service
 * without credentials.</p>
 */
@Component
public class CallerAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CallerAuthenticationFilter.class);

    private final ClientRegistry clientRegistry;
    private final BearerTokenVerifier bearerTokenVerifier;
    private final CscProperties properties;
    private final ObjectMapper objectMapper;

    public CallerAuthenticationFilter(ClientRegistry clientRegistry,
                                      BearerTokenVerifier bearerTokenVerifier,
                                      CscProperties properties,
                                      ObjectMapper objectMapper) {
        this.clientRegistry = clientRegistry;
        this.bearerTokenVerifier = bearerTokenVerifier;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /** Health and metrics stay open so a load balancer can probe the service. */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        if (path == null || path.isEmpty()) {
            path = request.getRequestURI();
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
                path = path.substring(contextPath.length());
            }
        }
        return path.startsWith("/actuator") || path.equals("/error");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            CallerContext.set(request, authenticate(request));
            MDC.put("client", CallerContext.require(request).clientId());
            chain.doFilter(request, response);
        } catch (OrchestratorException e) {
            log.info("Rejected {} {}: {}", request.getMethod(), request.getRequestURI(), e.description());
            writeError(response, e);
        } finally {
            MDC.remove("client");
        }
    }

    private AuthenticatedCaller authenticate(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            if (!properties.requireAuthentication()) {
                return AuthenticatedCaller.anonymous();
            }
            throw new OrchestratorException(ErrorCode.MISSING_AUTHORIZATION);
        }
        if (header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return bearerTokenVerifier.verify(header.substring(7).trim());
        }
        if (header.regionMatches(true, 0, "Basic ", 0, 6)) {
            return basic(header.substring(6).trim());
        }
        throw new OrchestratorException(ErrorCode.MISSING_AUTHORIZATION);
    }

    private AuthenticatedCaller basic(String encoded) {
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new OrchestratorException(ErrorCode.INVALID_CLIENT_CREDENTIALS, e);
        }
        int separator = decoded.indexOf(':');
        if (separator < 0) {
            throw new OrchestratorException(ErrorCode.INVALID_CLIENT_CREDENTIALS);
        }
        String clientId = decoded.substring(0, separator);
        String clientSecret = decoded.substring(separator + 1);
        clientRegistry.authenticate(clientId, clientSecret);
        return AuthenticatedCaller.client(clientId);
    }

    private void writeError(HttpServletResponse response, OrchestratorException e) throws IOException {
        response.setStatus(e.errorCode().status().value());
        response.setContentType("application/json;charset=UTF-8");
        if (e.errorCode().status().value() == 401) {
            response.setHeader("WWW-Authenticate", "Bearer, Basic realm=\"twokeyok-orchestrator\"");
        }
        objectMapper.writeValue(response.getOutputStream(),
                new ErrorResponse(e.errorCode().code(), e.description()));
    }
}
