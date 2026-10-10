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
import org.junit.jupiter.api.Test;
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

    /**
     * The SubFilter is written by the SDK into the document it prepares, so the
     * prepared document is taken from the SDK request - a private field, read
     * here only because there is no other way to see it before ADSS signs - and
     * finished with a placeholder signature. The digest must stay SHA-256 too.
     */
    @ParameterizedTest
    @CsvSource({"ETSI.CAdES.detached", "adbe.pkcs7.detached"})
    void writesTheConfiguredSubFilter(String subFilter) throws Exception {
        Path pdf = dir.resolve("unsigned-" + subFilter + ".pdf");
        assertThat(TestPdfGenerator.generate(pdf.toString())).isZero();

        AdssSigningBackend backend = new AdssSigningBackend(TestProperties.signing(Map.of()));
        PdfSigningRequest request = backend.buildRequest(job("SHA256", subFilter, Files.readAllBytes(pdf)));
        Path written = dir.resolve("request-" + subFilter + ".xml");
        request.writeTo(written.toString());
        Matcher digest = DIGEST.matcher(Files.readString(written, StandardCharsets.UTF_8));
        assertThat(digest.find()).isTrue();
        assertThat(Base64.getDecoder().decode(digest.group(1))).as("still SHA-256").hasSize(32);

        java.lang.reflect.Field signers = PdfSigningRequest.class.getDeclaredField("m_listPdfSigners");
        signers.setAccessible(true);
        Object signer = ((List<?>) signers.get(request)).get(0);
        signer.getClass().getMethod("embedSignature", byte[].class).invoke(signer, (Object) new byte[64]);
        byte[] prepared = (byte[]) signer.getClass().getMethod("getSignedDocument").invoke(signer);
        try (org.apache.pdfbox.pdmodel.PDDocument document = org.apache.pdfbox.pdmodel.PDDocument.load(prepared)) {
            assertThat(document.getSignatureDictionaries().get(0).getSubFilter()).isEqualTo(subFilter);
        }
    }

    /**
     * The second signer of a two-signature workflow sends back the first
     * signer's output. The SDK must append to it - every byte of the signed
     * document kept, so the first signature stays valid - and the new signature
     * must go into a field of its own.
     */
    @Test
    void signsADocumentSomeoneHasAlreadySigned() throws Exception {
        Path pdf = dir.resolve("unsigned-for-two.pdf");
        assertThat(TestPdfGenerator.generate(pdf.toString())).isZero();
        byte[] firstSigned = signLocally(Files.readAllBytes(pdf), "Signature1");

        SignJob.SignDocument document = new SignJob.SignDocument("signed-once.pdf", "application/pdf", firstSigned);
        String field = iq.twokeyok.orchestrator.signing.SignatureFieldNames.choose("Signature1", List.of(document));
        assertThat(field).isEqualTo("Signature2");

        SignJob second = job("SHA256", "ETSI.CAdES.detached", firstSigned);
        second = new SignJob(second.requestId(), second.config().withSignatureFieldName(field),
                second.appearance(), second.documents());
        PdfSigningRequest request = new AdssSigningBackend(TestProperties.signing(Map.of())).buildRequest(second);
        request.writeTo(dir.resolve("request-second.xml").toString());

        java.lang.reflect.Field signers = PdfSigningRequest.class.getDeclaredField("m_listPdfSigners");
        signers.setAccessible(true);
        Object signer = ((List<?>) signers.get(request)).get(0);
        signer.getClass().getMethod("embedSignature", byte[].class).invoke(signer, (Object) new byte[64]);
        byte[] twice = (byte[]) signer.getClass().getMethod("getSignedDocument").invoke(signer);

        assertThat(java.util.Arrays.copyOf(twice, firstSigned.length))
                .as("the first signed document is kept byte for byte").isEqualTo(firstSigned);
        try (org.apache.pdfbox.pdmodel.PDDocument loaded = org.apache.pdfbox.pdmodel.PDDocument.load(twice)) {
            assertThat(loaded.getSignatureDictionaries()).hasSize(2);
            assertThat(loaded.getSignatureDictionaries().get(1).getSubFilter()).isEqualTo("ETSI.CAdES.detached");
            assertThat(loaded.getDocumentCatalog().getAcroForm().getField("Signature2")).isNotNull();

            // And the first signature still verifies over its bytes.
            org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature first =
                    loaded.getSignatureDictionaries().get(0);
            org.bouncycastle.cms.CMSSignedData cms = new org.bouncycastle.cms.CMSSignedData(
                    new org.bouncycastle.cms.CMSProcessableByteArray(first.getSignedContent(twice)),
                    first.getContents(twice));
            org.bouncycastle.cms.SignerInformation signerInfo = cms.getSignerInfos().getSigners().iterator().next();
            org.bouncycastle.cert.X509CertificateHolder certificate = (org.bouncycastle.cert.X509CertificateHolder)
                    cms.getCertificates().getMatches(signerInfo.getSID()).iterator().next();
            assertThat(signerInfo.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC").build(certificate))).as("first signature intact").isTrue();
        }
    }

    /** An ordinary detached signature in {@code field}, as the first signer's request would return. */
    private static byte[] signLocally(byte[] pdf, String field) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair keys = generator.generateKeyPair();
        org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name("CN=First signer");
        org.bouncycastle.cert.X509CertificateHolder certificate = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                name, java.math.BigInteger.ONE, new java.util.Date(System.currentTimeMillis() - 86_400_000L),
                new java.util.Date(System.currentTimeMillis() + 86_400_000L), name, keys.getPublic())
                .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate()));
        try (org.apache.pdfbox.pdmodel.PDDocument document = org.apache.pdfbox.pdmodel.PDDocument.load(pdf)) {
            org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature signature =
                    new org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature();
            signature.setFilter(org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(field);
            signature.setSignDate(java.util.Calendar.getInstance());
            org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions options =
                    new org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions();
            document.addSignature(signature, content -> {
                try {
                    org.bouncycastle.cms.CMSSignedDataGenerator cms = new org.bouncycastle.cms.CMSSignedDataGenerator();
                    cms.addSignerInfoGenerator(new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                            new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build())
                            .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                                    .build(keys.getPrivate()), certificate));
                    // As ADSS does: the SDK reads existing signatures and needs their certificate.
                    cms.addCertificate(certificate);
                    return cms.generate(new org.bouncycastle.cms.CMSProcessableByteArray(content.readAllBytes()), false)
                            .getEncoded();
                } catch (Exception e) {
                    throw new java.io.IOException(e);
                }
            }, options);
            // PDFBox names the field it creates; make it the one the test expects.
            document.getDocumentCatalog().getAcroForm().getFields().get(0).setPartialName(field);
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    private static SignJob job(String algorithm, byte[] pdf) throws Exception {
        return job(algorithm, "adbe.pkcs7.detached", pdf);
    }

    private static SignJob job(String algorithm, String subFilter, byte[] pdf) throws Exception {
        EffectiveSignerConfig config = new EffectiveSignerConfig(
                "lab_eseal", SignerType.ESEAL, "Orchestrator-Signing", "adss:signing:profile:008",
                "lab_alias", null, null, algorithm, null, subFilter, 12000, "Signature1", 1,
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
