package iq.twokeyok.orchestrator.ops;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.Signer;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.signing.PadesLevel;

/**
 * {@code java -jar twokeyok-orchestrator.jar --check-adss} — reports whether the
 * configured ADSS endpoints and key material are reachable and usable from
 * <em>this</em> host, then exits.
 *
 * <p>Worth running before the first signing attempt on a new install. The
 * signing gateway is normally {@code localhost:8777} on the ADSS host and the
 * TSA often sits on a private address, so "it works from my laptop" and "it
 * works from the orchestrator" are different questions.</p>
 *
 * <p>It opens TCP connections and stats files. It never signs, never sends a
 * credential, and never prints a secret — only whether one is configured.</p>
 *
 * <p>Exit code is 0 when every <em>required</em> check passes, 1 otherwise, so
 * it can gate a deployment script.</p>
 */
@Component
public class AdssConnectivityCheck implements ApplicationRunner {

    public static final String FLAG = "check-adss";
    /** {@code --signer=<id>} limits the report to one configured identity. */
    public static final String SIGNER_FLAG = "signer";

    private static final int TIMEOUT_MS = 5000;
    private static final String PASS = "PASS";
    private static final String FAIL = "FAIL";
    private static final String WARN = "WARN";
    private static final String SKIP = "n/a ";

    private final SigningProperties properties;
    private final ApplicationContext context;

    public AdssConnectivityCheck(SigningProperties properties, ApplicationContext context) {
        this.properties = properties;
        this.context = context;
    }

    /** One line of the report. {@code required} drives the exit code. */
    private record Check(String status, String name, String detail, boolean required) {

        boolean failed() {
            return required && FAIL.equals(status);
        }
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!args.containsOption(FLAG)) {
            return;
        }

        // --signer=<id> scopes the report to one identity. Without it every
        // configured signer counts, which would fail an e-seal check on a RAS
        // endpoint only a natural person needs.
        String scope = args.getOptionValues(SIGNER_FLAG) == null || args.getOptionValues(SIGNER_FLAG).isEmpty()
                ? null : args.getOptionValues(SIGNER_FLAG).get(0);
        Map<String, Signer> scoped = scopedSigners(scope);

        boolean longTerm = scoped.values().stream()
                .anyMatch(signer -> PadesLevel.toSdkType(effectiveLevel(signer)) != null)
                || (scoped.isEmpty()
                        && PadesLevel.toSdkType(properties.dss().signature().signatureLevel()) != null);

        List<Check> checks = new ArrayList<>();
        checks.add(endpoint("Signing gateway", properties.gateway().url(), true));
        checks.add(signingServiceStatus(properties.gateway().url()));
        // Reported, never required. These are addresses handed to ADSS, through
        // setVerificationServiceAddress and setTimeStampServiceAddress, and ADSS
        // reaches them from its own network. A timeout here usually means a
        // wrong URL and is worth seeing, but a verification service firewalled
        // off from this host can be perfectly reachable from ADSS, so it is no
        // reason to refuse to sign.
        checks.add(endpoint("Verification", properties.verification().url(), false));
        checks.add(endpoint("Timestamp (TSA)", properties.dss().tsa().url(), false));
        checks.add(endpoint("OCSP", properties.dss().ocsp().url(), false));
        // Informational only. This backend drives the SDK, which reaches RAS
        // through the signing gateway — it never opens a connection to RAS
        // itself, so RAS being unreachable from this host does not stop a
        // natural-person signature.
        checks.add(endpoint("RAS", properties.ras().url(), false));
        checks.add(file("Client keystore", properties.ras().keystorePath(),
                properties.ras().keystorePassword(), false));
        checks.add(file("Truststore", properties.truststorePath(),
                properties.truststorePassword(), false));

        StringBuilder report = new StringBuilder();
        report.append(System.lineSeparator());
        report.append("ADSS PREFLIGHT").append(System.lineSeparator());
        report.append("==============").append(System.lineSeparator());
        // Without ORCHESTRATOR_CONFIG_DIR this reads ./config, or the defaults
        // packaged in the jar, and then reports on a deployment nobody is
        // running. Naming the source makes that obvious at a glance.
        String configDir = System.getenv("ORCHESTRATOR_CONFIG_DIR");
        report.append("  configuration: ")
                .append(configDir == null ? "./config (ORCHESTRATOR_CONFIG_DIR not set)" : configDir)
                .append(System.lineSeparator());
        if (scope != null) {
            report.append("  scoped to signer: ").append(scope)
                    .append(scoped.isEmpty() ? "  (NOT CONFIGURED)" : "")
                    .append(System.lineSeparator());
        }
        report.append(System.lineSeparator());

        report.append(row("STATUS", "CHECK", "DETAIL"));
        report.append(rule());
        for (Check check : checks) {
            report.append(row(check.status(), check.name(), check.detail()));
        }
        report.append(rule());
        report.append(System.lineSeparator());

        appendSigningProfiles(report, scoped);
        appendSignatureSettings(report, longTerm);

        boolean failed = checks.stream().anyMatch(Check::failed);
        report.append(System.lineSeparator());
        report.append("PRECHECK: ").append(failed ? FAIL : PASS).append(System.lineSeparator());
        if (failed) {
            report.append("  One or more required endpoints are unreachable. ")
                    .append("Signing will fail until they are.").append(System.lineSeparator());
        }

        System.out.print(report);
        System.exit(SpringApplication.exit(context, () -> failed ? 1 : 0));
    }

    // ------------------------------------------------------------------
    // Effective configuration
    // ------------------------------------------------------------------

    /**
     * The signers the report covers: one when {@code --signer} names it, every
     * configured signer otherwise. An unknown name yields none, which the header
     * states rather than silently widening the scope.
     */
    private Map<String, Signer> scopedSigners(String scope) {
        if (scope == null) {
            return properties.signers();
        }
        Signer signer = properties.signers().get(scope);
        return signer == null ? Map.of() : Map.of(scope, signer);
    }

    /** A signer may override the signature level, which decides whether a TSA is needed. */
    private String effectiveLevel(Signer signer) {
        String override = signer.overrides() == null ? null : signer.overrides().signatureLevel();
        return override != null ? override : properties.dss().signature().signatureLevel();
    }

    /**
     * The profile actually used per signer, after the signer entry falls back to
     * {@code signing.gateway.pdf_profile_id}. This is what ADSS will be asked for,
     * which is usually the first thing wrong on a new install.
     */
    private void appendSigningProfiles(StringBuilder report, Map<String, Signer> signers) {
        report.append("EFFECTIVE SIGNING PROFILE").append(System.lineSeparator());
        report.append(rule());
        report.append(row("TYPE", "SIGNER", "PROFILE / CREDENTIAL"));
        report.append(rule());

        String gatewayDefault = properties.gateway().pdfProfileId();
        if (signers.isEmpty()) {
            report.append(row(SKIP, "(none configured)", "gateway default: " + orDash(gatewayDefault)));
        }
        for (Map.Entry<String, Signer> entry : signers.entrySet()) {
            Signer signer = entry.getValue();
            String profile = firstNonBlank(signer.profileId(), gatewayDefault);
            String credential = firstNonBlank(signer.certificateAlias(), signer.credentialId());
            String detail = "profile=" + orDash(profile)
                    + "  credential=" + (credential == null
                            ? "(strategy " + properties.defaultCredentialStrategy() + ")" : credential);
            String status = profile == null ? FAIL : signer.enabled() ? PASS : WARN;
            report.append(row(status,
                    entry.getKey() + (signer.enabled() ? "" : " (disabled)"),
                    detail));
            report.append(row("", "  type " + signer.type(),
                    signer.type() == SignerType.NATURAL_PERSON
                            ? "user_id=" + orDash(firstNonBlank(signer.userId(), entry.getKey()))
                                    + "  require_pin=" + signer.requirePin()
                            : "unattended seal"));
        }
        report.append(rule());
        report.append(System.lineSeparator());
    }

    private void appendSignatureSettings(StringBuilder report, boolean longTerm) {
        SigningProperties.Signature signature = properties.dss().signature();
        report.append("EFFECTIVE SIGNATURE SETTINGS").append(System.lineSeparator());
        report.append(rule());
        report.append(setting("signature_level", signature.signatureLevel()
                + " -> SDK " + orDash(PadesLevel.toSdkType(signature.signatureLevel()))
                + (longTerm ? "  (needs verification + TSA)" : "  (produced by the ADSS profile)")));
        report.append(setting("hash_algorithm", signature.hashAlgorithm()));
        report.append(setting("dictionary_size", String.valueOf(signature.dictionarySize())));
        report.append(setting("compute_hash", String.valueOf(signature.computeHash())));
        report.append(setting("local_hash", String.valueOf(signature.localHash())));
        report.append(setting("signature_field", signature.signatureFieldName()
                + "  page " + signature.signingPage()));
        report.append(setting("container_type", signature.containerType()));
        report.append(setting("credential_strategy", properties.defaultCredentialStrategy().name()));
        report.append(setting("gateway request_mode", properties.gateway().requestMode()));
        report.append(setting("authorisation budget",
                properties.gateway().statusPolling().budgetMs() / 1000 + " s"
                        + " (" + properties.gateway().statusPolling().intervalMs() + " ms x "
                        + properties.gateway().statusPolling().maxAttempts() + ")"));
        report.append(setting("appearance", signature.appearance().enabled()
                ? signature.appearance().appearances().size() + " configured, "
                        + "use_default=" + signature.appearance().useDefault()
                : "disabled (no visible signature)"));
        report.append(rule());
    }

    // ------------------------------------------------------------------
    // Individual checks
    // ------------------------------------------------------------------

    /**
     * Asks the Signing Service whether it is running, which a TCP connection
     * cannot tell you.
     *
     * <p>A stopped Signing Service still accepts connections — the container is
     * up, the module is not — so the gateway check passes and every signature
     * then fails. Over the DSS interface ADSS states its status in response
     * headers, so an obviously invalid document is enough to read it back:</p>
     *
     * <pre>
     * RESPONSE_STATUS: FAILED
     * ERROR_CODE: 41003
     * MESSAGE: [Error-41003] Failed to process request - Signing service is stopped
     * </pre>
     *
     * <p>Any other error code means the service is running and rejected the
     * probe, which is the expected and healthy answer. No credential is sent and
     * nothing is signed.</p>
     */
    private static Check signingServiceStatus(String url) {
        String name = "Signing service";
        if (url == null || url.isBlank()) {
            return new Check(SKIP, name, "no gateway configured", false);
        }
        try {
            java.net.HttpURLConnection connection =
                    (java.net.HttpURLConnection) URI.create(url).toURL().openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setRequestProperty("Content-Type", "text/xml;charset=UTF-8");
            connection.setDoOutput(true);
            connection.getOutputStream().write("<probe/>".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            connection.getOutputStream().flush();

            String code = connection.getHeaderField("ERROR_CODE");
            String message = connection.getHeaderField("MESSAGE");
            connection.disconnect();

            if (code == null) {
                // No ADSS headers at all: something in front of ADSS answered.
                // A WAF block page and a container error page look identical here.
                return new Check(WARN, name,
                        "no ADSS status headers in the reply (HTTP " + connection.getResponseCode()
                                + ") — a proxy or firewall may be answering; see docs/TROUBLESHOOTING.md",
                        false);
            }
            if ("41003".equals(code.trim())) {
                return new Check(FAIL, name,
                        "STOPPED — " + (message == null ? "ADSS error 41003" : message.trim()), true);
            }
            return new Check(PASS, name, "running (rejected the probe with " + code.trim() + ", as expected)", false);
        } catch (Exception e) {
            return new Check(WARN, name, "could not probe: " + e.getMessage(), false);
        }
    }

    private static Check endpoint(String name, String url, boolean required) {
        if (isBlank(url)) {
            return new Check(required ? FAIL : SKIP, name,
                    required ? "not configured (required)" : "not configured", required);
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return new Check(FAIL, name, "invalid URL: " + url, required);
        }
        if (uri.getHost() == null) {
            return new Check(FAIL, name, "no host in URL: " + url, required);
        }
        int port = uri.getPort() > 0 ? uri.getPort()
                : "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
        String target = uri.getHost() + ":" + port;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(uri.getHost(), port), TIMEOUT_MS);
            return new Check(PASS, name, target, required);
        } catch (IOException e) {
            return new Check(required ? FAIL : WARN, name,
                    target + " — " + e.getMessage(), required);
        }
    }

    /**
     * Reports whether key material exists and is readable — never its password.
     *
     * <p>Readability is reported for whoever runs the preflight, which is usually
     * root, while the service runs as its own account. A root-readable file can
     * still be unreadable to the service, so the owner and mode are printed too:
     * that is the difference between a PASS here and a
     * {@code FileNotFoundException (Permission denied)} at the first signature.</p>
     */
    private static Check file(String name, String path, String password, boolean required) {
        if (isBlank(path)) {
            return new Check(required ? FAIL : SKIP, name, "not configured", required);
        }
        Path file = Path.of(path);
        String passwordNote = isBlank(password) ? "  [no password set]" : "  [password set]";
        if (!Files.exists(file)) {
            return new Check(required ? FAIL : WARN, name, "missing: " + file.toAbsolutePath(), required);
        }
        if (!Files.isReadable(file)) {
            return new Check(FAIL, name,
                    "unreadable by this user: " + file.toAbsolutePath() + " (check owner and mode)", true);
        }
        return new Check(PASS, name, file.toAbsolutePath() + passwordNote + ownership(file), required);
    }

    /** {@code owner:group mode} so a mismatch with the service account is visible. */
    private static String ownership(Path file) {
        try {
            java.nio.file.attribute.PosixFileAttributes attributes = Files.readAttributes(
                    file, java.nio.file.attribute.PosixFileAttributes.class);
            return "  [%s:%s %s]".formatted(
                    attributes.owner().getName(),
                    attributes.group().getName(),
                    java.nio.file.attribute.PosixFilePermissions.toString(attributes.permissions()));
        } catch (Exception e) {
            return "";
        }
    }

    // ------------------------------------------------------------------
    // Formatting
    // ------------------------------------------------------------------

    private static String row(String status, String name, String detail) {
        return String.format("  %-6s | %-22s | %s%n", status, name, detail);
    }

    private static String setting(String name, String value) {
        return String.format("  %-22s : %s%n", name, value);
    }

    private static String rule() {
        return "  " + "-".repeat(94) + System.lineSeparator();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String orDash(String value) {
        return isBlank(value) ? "(not set)" : value;
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (!isBlank(candidate)) {
                return candidate;
            }
        }
        return null;
    }
}
