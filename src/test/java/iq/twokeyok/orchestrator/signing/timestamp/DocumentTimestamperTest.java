package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.ops.PdfSignatureInspector;
import iq.twokeyok.orchestrator.ops.TestPdfGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The document timestamp against a local RFC 3161 TSA, checked with the same
 * inspector operators run as {@code --verify-pdf}.
 */
class DocumentTimestamperTest {

    private static final String POLICY = "1.2.3.4.5";

    /** How the fake TSA answers the next request. */
    enum Mode { GRANT, REJECT, WRONG_IMPRINT }

    private static final AtomicReference<Mode> mode = new AtomicReference<>(Mode.GRANT);
    private static HttpServer server;
    private static String tsaUrl;
    private static KeyPair signerKeys;
    private static X509Certificate signerCert;

    @TempDir
    Path dir;

    @BeforeAll
    static void startTsa() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPair tsaKeys = keys();
        X509Certificate tsaCert = certificate("CN=Test TSA", tsaKeys, true);
        TimeStampTokenGenerator tokens = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", tsaKeys.getPrivate(), tsaCert),
                new JcaDigestCalculatorProviderBuilder().build().get(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier(POLICY));
        tokens.addCertificates(new JcaCertStore(List.of(tsaCert)));
        TimeStampResponseGenerator responses = new TimeStampResponseGenerator(tokens, TSPAlgorithms.ALLOWED);

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/tsa", exchange -> {
            try (InputStream in = exchange.getRequestBody()) {
                TimeStampRequest request = new TimeStampRequest(in.readAllBytes());
                byte[] reply = switch (mode.get()) {
                    case GRANT -> responses.generate(request, BigInteger.ONE, new Date()).getEncoded();
                    case REJECT -> responses.generateRejectedResponse(
                            new Exception("policy not accepted")).getEncoded();
                    case WRONG_IMPRINT -> {
                        // A valid token, but for different data than was asked.
                        byte[] other = new byte[32];
                        Arrays.fill(other, (byte) 7);
                        TimeStampRequestGenerator g = new TimeStampRequestGenerator();
                        g.setCertReq(true);
                        g.setReqPolicy(new ASN1ObjectIdentifier(POLICY));
                        TimeStampRequest forged = g.generate(TSPAlgorithms.SHA256, other, request.getNonce());
                        yield responses.generate(forged, BigInteger.TWO, new Date()).getEncoded();
                    }
                };
                exchange.getResponseHeaders().add("Content-Type", "application/timestamp-reply");
                exchange.sendResponseHeaders(200, reply.length);
                exchange.getResponseBody().write(reply);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
        tsaUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/tsa";

        signerKeys = keys();
        signerCert = certificate("CN=Test e-Seal", signerKeys, false);
    }

    @AfterAll
    static void stopTsa() {
        server.stop(0);
    }

    @BeforeEach
    void grantByDefault() {
        mode.set(Mode.GRANT);
    }

    @Test
    void appendsADocumentTimestampThatVerifiesAndKeepsTheSignatureValid() throws Exception {
        byte[] signed = signedPdf();

        byte[] stamped = timestamper().timestamp(signed, "test");

        // An incremental update: every byte of the signed document is kept as is.
        assertThat(Arrays.copyOf(stamped, signed.length)).isEqualTo(signed);
        try (PDDocument document = PDDocument.load(stamped)) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            assertThat(signatures).hasSize(2);
            assertThat(signatures.get(1).getSubFilter()).isEqualTo("ETSI.RFC3161");
            assertThat(signatures.get(1).getCOSObject().getNameAsString("Type")).isEqualTo("DocTimeStamp");
        }
        Path file = Files.write(dir.resolve("stamped.pdf"), stamped);
        assertThat(PdfSignatureInspector.inspect(file.toString()))
                .as("signature and document timestamp both verify").isZero();
    }

    @Test
    void reportsARefusalAsTsaRejected() throws Exception {
        mode.set(Mode.REJECT);
        byte[] signed = signedPdf();

        assertThatThrownBy(() -> timestamper().timestamp(signed, "test"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TSA_REJECTED);
    }

    @Test
    void neverEmbedsATokenForOtherData() throws Exception {
        mode.set(Mode.WRONG_IMPRINT);
        byte[] signed = signedPdf();

        assertThatThrownBy(() -> timestamper().timestamp(signed, "test"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TSA_REJECTED);
    }

    @Test
    void reportsAnUnreachableTsaAsUnavailable() throws Exception {
        byte[] signed = signedPdf();
        DocumentTimestamper unreachable = new DocumentTimestamper(
                new TsaClient("http://127.0.0.1:1/tsa", POLICY, "SHA256", 2000, null, null));

        assertThatThrownBy(() -> unreachable.timestamp(signed, "test"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TSA_UNAVAILABLE);
    }

    @Test
    void isOffUnlessConfigured() throws Exception {
        DocumentTimestamper off = new DocumentTimestamper((TsaClient) null);
        byte[] signed = signedPdf();

        assertThat(off.isEnabled()).isFalse();
        assertThat(off.timestamp(signed, "test")).isSameAs(signed);
    }

    // ------------------------------------------------------------------

    private static DocumentTimestamper timestamper() {
        return new DocumentTimestamper(new TsaClient(tsaUrl, POLICY, "SHA256", 5000, null, null));
    }

    /** A test PDF with an ordinary detached CMS signature, as ADSS would return it. */
    private byte[] signedPdf() throws Exception {
        Path unsigned = dir.resolve("unsigned-" + System.nanoTime() + ".pdf");
        assertThat(TestPdfGenerator.generate(unsigned.toString())).isZero();
        try (PDDocument document = PDDocument.load(unsigned.toFile())) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Test e-Seal");
            signature.setSignDate(Calendar.getInstance());
            document.addSignature(signature, content -> {
                try {
                    CMSSignedDataGenerator cms = new CMSSignedDataGenerator();
                    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signerKeys.getPrivate());
                    cms.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().build()).build(signer, signerCert));
                    cms.addCertificates(new JcaCertStore(List.of(signerCert)));
                    return cms.generate(new CMSProcessableByteArray(content.readAllBytes()), false).getEncoded();
                } catch (Exception e) {
                    throw new java.io.IOException(e);
                }
            });
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(String dn, KeyPair keys, boolean tsa) throws Exception {
        Date from = new Date(System.currentTimeMillis() - 86_400_000L);
        Date to = new Date(System.currentTimeMillis() + 86_400_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(dn), BigInteger.valueOf(System.nanoTime()), from, to, new X500Name(dn), keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if (tsa) {
            // RFC 3161: a TSA certificate carries exactly this critical purpose.
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        }
        X509CertificateHolder holder = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate()));
        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
