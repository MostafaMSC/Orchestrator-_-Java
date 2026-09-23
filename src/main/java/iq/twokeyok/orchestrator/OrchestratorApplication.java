package iq.twokeyok.orchestrator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import iq.twokeyok.orchestrator.ops.AdssConnectivityCheck;
import iq.twokeyok.orchestrator.ops.PdfSignatureInspector;
import iq.twokeyok.orchestrator.ops.TestPdfGenerator;

import iq.twokeyok.orchestrator.config.CscProperties;
import iq.twokeyok.orchestrator.config.SigningProperties;

/**
 * TwoKeyOk MiddleWare Orchestrator.
 *
 * <p>A middleware between business applications and the ADSS RAS / SAM signing
 * platform. This release exposes the two endpoints the integration needs first:
 * {@code POST /service/sign} (PAdES) and
 * {@code GET /service/signing/appearances/list}, for both e-seal and natural
 * person signing.</p>
 */
@SpringBootApplication
@EnableConfigurationProperties({SigningProperties.class, CscProperties.class})
public class OrchestratorApplication {

    /** CLI switch that prints a BCrypt hash for a client secret and exits. */
    private static final String HASH_SECRET = "--hash-secret";
    /** Writes a small unsigned PDF for the end-to-end signing test. */
    private static final String MAKE_TEST_PDF = "--make-test-pdf";
    /** Checks that a PDF really carries a signature that verifies. */
    private static final String VERIFY_PDF = "--verify-pdf";

    public static void main(String[] args) {
        // These three need no configuration and no application context, so they
        // run before Spring starts and exit with their own status code.
        if (args.length > 0 && HASH_SECRET.equals(args[0])) {
            hashSecret(args);
            return;
        }
        if (args.length > 0 && MAKE_TEST_PDF.equals(args[0])) {
            System.exit(TestPdfGenerator.generate(requireArgument(args, MAKE_TEST_PDF, "<file>")));
        }
        if (args.length > 0 && VERIFY_PDF.equals(args[0])) {
            System.exit(PdfSignatureInspector.inspect(requireArgument(args, VERIFY_PDF, "<file>")));
        }
        SpringApplication application = new SpringApplication(OrchestratorApplication.class);
        // The connectivity preflight reads the configuration and exits; it must not
        // bind the listener, or it would clash with the running service.
        for (String arg : args) {
            if (arg.equals("--" + AdssConnectivityCheck.FLAG)) {
                application.setWebApplicationType(WebApplicationType.NONE);
                break;
            }
        }
        application.run(args);
    }

    /**
     * {@code java -jar twokeyok-orchestrator.jar --hash-secret '<secret>'} prints
     * the value to put in {@code security.clients.<id>.secret-hash}, so an
     * installation never has to store a plain client secret.
     */
    private static void hashSecret(String[] args) {
        String secret = args.length > 1 ? args[1] : null;
        if (secret == null || secret.isEmpty()) {
            System.err.println("Usage: java -jar twokeyok-orchestrator.jar " + HASH_SECRET + " <client-secret>");
            System.exit(2);
            return;
        }
        System.out.println(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(12).encode(secret));
    }

    private static String requireArgument(String[] args, String flag, String placeholder) {
        if (args.length < 2 || args[1].isBlank()) {
            System.err.println("Usage: java -jar twokeyok-orchestrator.jar " + flag + " " + placeholder);
            System.exit(2);
        }
        return args[1];
    }
}
