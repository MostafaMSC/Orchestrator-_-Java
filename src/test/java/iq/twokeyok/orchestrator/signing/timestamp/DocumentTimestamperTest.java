package iq.twokeyok.orchestrator.signing.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
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
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
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

    /** How the fake OCSP responder answers the next request. */
    enum Ocsp { GOOD, REVOKED, DOWN }

    private static final AtomicReference<Mode> mode = new AtomicReference<>(Mode.GRANT);
    private static final AtomicReference<Ocsp> ocspMode = new AtomicReference<>(Ocsp.GOOD);
    /** Every CA the fake responder answers for, with its key. */
    private static final Map<X509CertificateHolder, KeyPair> cas = new java.util.LinkedHashMap<>();
    private static HttpServer server;
    private static String tsaUrl;
    private static X509Certificate tsaCert;
    private static KeyPair signerKeys;
    private static X509Certificate signerCert;
    private static KeyPair signerCaKeys;
    private static X509Certificate signerCaCert;

    @TempDir
    Path dir;

    @BeforeAll
    static void startTsa() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();

        // The staging shape: a root issues an intermediate that names no OCSP
        // responder, which issues the TSA certificate that does name one. The
        // one responder answers for both CAs.
        KeyPair rootKeys = keys();
        X509Certificate rootCert = certificate("CN=Test TSA Root", rootKeys, null, rootKeys, true, false, null);
        KeyPair caKeys = keys();
        X509Certificate caCert = certificate("CN=Test TSA CA", caKeys, rootCert, rootKeys, true, false, null);
        KeyPair tsaKeys = keys();
        tsaCert = certificate("CN=Test TSA", tsaKeys, caCert, caKeys, false, true, base + "/ocsp");

        TimeStampTokenGenerator tokens = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", tsaKeys.getPrivate(), tsaCert),
                new JcaDigestCalculatorProviderBuilder().build().get(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier(POLICY));
        tokens.addCertificates(new JcaCertStore(List.of(tsaCert, caCert, rootCert)));
        TimeStampResponseGenerator responses = new TimeStampResponseGenerator(tokens, TSPAlgorithms.ALLOWED);

        // The e-seal's own chain: a CA (naming no responder) and the signer
        // certificate, which names the same responder.
        signerCaKeys = keys();
        signerCaCert = certificate("CN=Test e-Seal CA", signerCaKeys, null, signerCaKeys, true, false, null);
        signerKeys = keys();
        signerCert = certificate("CN=Test e-Seal", signerKeys, signerCaCert, signerCaKeys, false, false,
                base + "/ocsp");

        cas.put(new X509CertificateHolder(rootCert.getEncoded()), rootKeys);
        cas.put(new X509CertificateHolder(caCert.getEncoded()), caKeys);
        cas.put(new X509CertificateHolder(signerCaCert.getEncoded()), signerCaKeys);
        server.createContext("/ocsp", exchange -> {
            try (InputStream in = exchange.getRequestBody()) {
                if (ocspMode.get() == Ocsp.DOWN) {
                    exchange.sendResponseHeaders(503, -1);
                    return;
                }
                OCSPReq request = new OCSPReq(in.readAllBytes());
                // Answer as whichever CA issued the certificate asked about.
                CertificateID id = request.getRequestList()[0].getCertID();
                X509CertificateHolder issuer = null;
                for (X509CertificateHolder ca : cas.keySet()) {
                    if (id.matchesIssuer(ca, new JcaDigestCalculatorProviderBuilder().build())) {
                        issuer = ca;
                    }
                }
                byte[] reply = ocspResponse(issuer, cas.get(issuer), id, ocspMode.get() == Ocsp.GOOD);
                exchange.getResponseHeaders().add("Content-Type", "application/ocsp-response");
                exchange.sendResponseHeaders(200, reply.length);
                exchange.getResponseBody().write(reply);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
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
        tsaUrl = base + "/tsa";
    }

    private static byte[] ocspResponse(X509CertificateHolder issuer, KeyPair issuerKeys, CertificateID id,
                                       boolean good) throws Exception {
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(issuer.getSubject()));
        builder.addResponse(id, good ? CertificateStatus.GOOD
                : new RevokedStatus(new Date(), CRLReason.keyCompromise));
        BasicOCSPResp basic = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate()),
                new X509CertificateHolder[] {issuer}, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    @AfterAll
    static void stopTsa() {
        server.stop(0);
    }

    @BeforeEach
    void grantByDefault() {
        mode.set(Mode.GRANT);
        ocspMode.set(Ocsp.GOOD);
    }

    @Test
    void addsTheValidationDataForTheSignerAndTheTsaToTheDss() throws Exception {
        byte[] signed = signedPdf(null);

        byte[] stamped = timestamperWithValidationData().timestamp(signed, "test");

        assertThat(Arrays.copyOf(stamped, signed.length)).isEqualTo(signed);
        try (PDDocument document = PDDocument.load(stamped)) {
            COSDictionary dss = (COSDictionary) document.getDocumentCatalog().getCOSObject()
                    .getDictionaryObject(COSName.getPDFName("DSS"));
            assertThat(dss).as("/DSS present").isNotNull();
            COSArray certs = (COSArray) dss.getDictionaryObject(COSName.getPDFName("Certs"));
            assertThat(certs.size()).as("e-seal certificate and its CA; TSA, its CA and root").isEqualTo(5);
            assertThat(coveredSerials(dss)).as("e-seal certificate; TSA certificate and its CA")
                    .containsExactlyInAnyOrder(signerCert.getSerialNumber(), tsaCert.getSerialNumber(),
                            cas.keySet().stream().filter(c -> c.getSubject().toString().equals("CN=Test TSA CA"))
                                    .findFirst().orElseThrow().getSerialNumber());

            // The signature's validation data is written before the document
            // timestamp, so the timestamp covers it.
            PDSignature timestamp = document.getSignatureDictionaries().get(1);
            int[] range = timestamp.getByteRange();
            assertThat(indexOf(stamped, "/DSS".getBytes(StandardCharsets.US_ASCII)))
                    .isBetween(0, range[2] + range[3]);
        }
        Path file = Files.write(dir.resolve("stamped-ltv.pdf"), stamped);
        assertThat(PdfSignatureInspector.inspect(file.toString()))
                .as("signature and document timestamp still verify after the /DSS updates").isZero();
    }

    @Test
    void usesTheResponseAdssEmbeddedWhenTheResponderCannotBeReached() throws Exception {
        CertificateID id = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new X509CertificateHolder(signerCaCert.getEncoded()), signerCert.getSerialNumber());
        byte[] embedded = ocspResponse(new X509CertificateHolder(signerCaCert.getEncoded()), signerCaKeys, id, true);
        byte[] signed = signedPdf(embedded);
        ocspMode.set(Ocsp.DOWN);

        byte[] stamped = timestamperWithValidationData().timestamp(signed, "test");

        try (PDDocument document = PDDocument.load(stamped)) {
            COSDictionary dss = (COSDictionary) document.getDocumentCatalog().getCOSObject()
                    .getDictionaryObject(COSName.getPDFName("DSS"));
            assertThat(coveredSerials(dss)).containsExactly(signerCert.getSerialNumber());
        }
        Path file = Files.write(dir.resolve("stamped-embedded.pdf"), stamped);
        assertThat(PdfSignatureInspector.inspect(file.toString())).isZero();
    }

    @Test
    void stillReturnsTheTimestampedDocumentWhenOcspIsDown() throws Exception {
        ocspMode.set(Ocsp.DOWN);
        byte[] stamped = timestamperWithValidationData().timestamp(signedPdf(null), "test");

        assertThat(responsesIn(stamped)).isZero();
        Path file = Files.write(dir.resolve("stamped-no-ocsp.pdf"), stamped);
        assertThat(PdfSignatureInspector.inspect(file.toString())).isZero();
    }

    @Test
    void neverEmbedsARevokedStatusAsValidationData() throws Exception {
        ocspMode.set(Ocsp.REVOKED);
        byte[] stamped = timestamperWithValidationData().timestamp(signedPdf(null), "test");

        assertThat(responsesIn(stamped)).isZero();
    }

    private static List<BigInteger> coveredSerials(COSDictionary dss) throws Exception {
        List<BigInteger> covered = new java.util.ArrayList<>();
        COSArray ocsps = (COSArray) dss.getDictionaryObject(COSName.getPDFName("OCSPs"));
        for (int i = 0; ocsps != null && i < ocsps.size(); i++) {
            try (InputStream in = ((COSStream) ocsps.getObject(i)).createInputStream()) {
                SingleResp single = ((BasicOCSPResp) new OCSPResp(in.readAllBytes()).getResponseObject())
                        .getResponses()[0];
                assertThat(single.getCertStatus()).isEqualTo(CertificateStatus.GOOD);
                covered.add(single.getCertID().getSerialNumber());
            }
        }
        return covered;
    }

    private static int responsesIn(byte[] pdf) throws Exception {
        try (PDDocument document = PDDocument.load(pdf)) {
            Object dss = document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.getPDFName("DSS"));
            return dss == null ? 0 : coveredSerials((COSDictionary) dss).size();
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    @Test
    void appendsADocumentTimestampThatVerifiesAndKeepsTheSignatureValid() throws Exception {
        byte[] signed = signedPdf(null);

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
        byte[] signed = signedPdf(null);

        assertThatThrownBy(() -> timestamper().timestamp(signed, "test"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TSA_REJECTED);
    }

    @Test
    void neverEmbedsATokenForOtherData() throws Exception {
        mode.set(Mode.WRONG_IMPRINT);
        byte[] signed = signedPdf(null);

        assertThatThrownBy(() -> timestamper().timestamp(signed, "test"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.TSA_REJECTED);
    }

    @Test
    void reportsAnUnreachableTsaAsUnavailable() throws Exception {
        byte[] signed = signedPdf(null);
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
        byte[] signed = signedPdf(null);

        assertThat(off.isEnabled()).isFalse();
        assertThat(off.timestamp(signed, "test")).isSameAs(signed);
    }

    // ------------------------------------------------------------------

    private static DocumentTimestamper timestamper() {
        return new DocumentTimestamper(new TsaClient(tsaUrl, POLICY, "SHA256", 5000, null, null));
    }

    private static DocumentTimestamper timestamperWithValidationData() {
        return new DocumentTimestamper(new TsaClient(tsaUrl, POLICY, "SHA256", 5000, null, null),
                new LongTermValidationData(new OcspClient(5000)));
    }

    private static boolean hasDss(byte[] pdf) throws Exception {
        try (PDDocument document = PDDocument.load(pdf)) {
            return document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.getPDFName("DSS")) != null;
        }
    }

    /**
     * A test PDF with an ordinary detached CMS signature, as ADSS would return it.
     *
     * @param embeddedOcsp an OCSP response to carry in the signature the way
     *                     ADSS does ({@code adbe-revocationInfoArchival}), or
     *                     {@code null}
     */
    private byte[] signedPdf(byte[] embeddedOcsp) throws Exception {
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
                    JcaSignerInfoGeneratorBuilder info = new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().build());
                    if (embeddedOcsp != null) {
                        // RevocationInfoArchival ::= SEQUENCE { ocsp [1] EXPLICIT SEQUENCE OF OCSPResponse }
                        org.bouncycastle.asn1.DERSequence archival = new org.bouncycastle.asn1.DERSequence(
                                new org.bouncycastle.asn1.DERTaggedObject(true, 1,
                                        new org.bouncycastle.asn1.DERSequence(
                                                org.bouncycastle.asn1.ocsp.OCSPResponse.getInstance(embeddedOcsp))));
                        org.bouncycastle.asn1.cms.Attribute attribute = new org.bouncycastle.asn1.cms.Attribute(
                                new ASN1ObjectIdentifier("1.2.840.113583.1.1.8"),
                                new org.bouncycastle.asn1.DERSet(archival));
                        info.setSignedAttributeGenerator(new org.bouncycastle.cms.DefaultSignedAttributeTableGenerator(
                                new org.bouncycastle.asn1.cms.AttributeTable(attribute)));
                    }
                    cms.addSignerInfoGenerator(info.build(signer, signerCert));
                    cms.addCertificates(new JcaCertStore(List.of(signerCert, signerCaCert)));
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

    /**
     * @param issuer    {@code null} for a self-signed certificate
     * @param ocspUrl   written into Authority Information Access when not {@code null}
     */
    private static X509Certificate certificate(String dn, KeyPair keys, X509Certificate issuer, KeyPair issuerKeys,
                                               boolean ca, boolean tsa, String ocspUrl) throws Exception {
        Date from = new Date(System.currentTimeMillis() - 86_400_000L);
        Date to = new Date(System.currentTimeMillis() + 86_400_000L);
        X500Name issuerName = issuer == null ? new X500Name(dn)
                : new X500Name(issuer.getSubjectX500Principal().getName());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, BigInteger.valueOf(System.nanoTime()), from, to, new X500Name(dn), keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (tsa) {
            // RFC 3161: a TSA certificate carries exactly this critical purpose.
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        }
        if (ocspUrl != null) {
            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                    AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }
        X509CertificateHolder holder = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate()));
        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
