package iq.twokeyok.orchestrator.signing.adss;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

import com.ascertia.adss.client.api.signing.PdfSigningRequest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import iq.twokeyok.orchestrator.TestProperties;
import iq.twokeyok.orchestrator.appearance.AppearanceService.TextDefaults;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate;
import iq.twokeyok.orchestrator.appearance.AppearanceXmlWriter;
import iq.twokeyok.orchestrator.appearance.ResolvedAppearance;
import iq.twokeyok.orchestrator.config.SigningProperties.SignerType;
import iq.twokeyok.orchestrator.ops.TestPdfGenerator;
import iq.twokeyok.orchestrator.signing.EffectiveSignerConfig;
import iq.twokeyok.orchestrator.signing.SignJob;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Under {@code local_hash} the digest sent to ADSS must be computed with the
 * configured algorithm.
 *
 * <p>Left to its default PDF signature mode, the SDK hashes in the legacy
 * enveloping form and always sends SHA-1, whatever {@code setHashAlgorithm}
 * says. ADSS then signed that SHA-1 value under a SHA-256 SignerInfo and the
 * resulting PDF failed verification in every reader. The request is built and
 * written locally here; nothing is sent.</p>
 */
class AdssLocalHashRequestTest {

    private static final Pattern DIGEST = Pattern.compile("DigestValue>([^<]+)<");

    @TempDir
    static Path dir;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @ParameterizedTest
    @CsvSource({"SHA256, 32", "SHA384, 48", "SHA512, 64"})
    void sendsADigestOfTheConfiguredAlgorithm(String algorithm, int digestLength) throws Exception {
        Path pdf = dir.resolve("unsigned-" + algorithm + ".pdf");
        assertThat(TestPdfGenerator.generate(pdf.toString())).isZero();

        AdssSigningBackend backend = new AdssSigningBackend(TestProperties.signing(Map.of()));
        PdfSigningRequest request = backend.buildRequest(job(algorithm, Files.readAllBytes(pdf)));

        Path written = dir.resolve("request-" + algorithm + ".xml");
        request.writeTo(written.toString());
        Matcher digest = DIGEST.matcher(Files.readString(written, StandardCharsets.UTF_8));

        assertThat(digest.find()).as("the request carries a document digest").isTrue();
        assertThat(Base64.getDecoder().decode(digest.group(1))).hasSize(digestLength);
    }

    private static SignJob job(String algorithm, byte[] pdf) throws Exception {
        EffectiveSignerConfig config = new EffectiveSignerConfig(
                "lab_eseal", SignerType.ESEAL, "Orchestrator-Signing", "adss:signing:profile:008",
                "lab_alias", null, null, algorithm, null, 12000, "Signature1", 1,
                true, false, null, "NONE", null, TextDefaults.EMPTY, true, true, true);
        ResolvedAppearance appearance = new ResolvedAppearance(
                "eseal_signature_appearance", appearanceXml(), "Lab e-Seal",
                null, null, null, null, null, null,
                new ResolvedAppearance.SignatureBox(50, 50, 230, 90, 1));
        return new SignJob("test-request", config, appearance,
                List.of(new SignJob.SignDocument("unsigned.pdf", "application/pdf", pdf)));
    }

    private static byte[] appearanceXml() throws Exception {
        ObjectMapper mapper = new ObjectMapper()
                .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        AppearanceTemplate template;
        try (var in = AdssLocalHashRequestTest.class.getResourceAsStream(
                "/appearances/eseal_signature_appearance.json")) {
            template = mapper.readValue(in, AppearanceTemplate.class);
        }
        return new AppearanceXmlWriter().write(template,
                Map.of(AppearanceTemplate.Fields.SIGNED_BY, "Lab e-Seal"), Map.of());
    }
}
