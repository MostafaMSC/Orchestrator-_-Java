package iq.twokeyok.orchestrator.signing.timestamp;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Who may sign an OCSP response, checked offline.
 */
class OcspClientTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Seen on staging with "TS TSA CA G1": the CA's key and the delegated
     * responder's key are of different types. Verifying the response with the
     * CA's key then throws instead of returning false, and that used to end the
     * check before the responder that really signed it was tried.
     */
    @Test
    void acceptsADelegatedResponderWhoseKeyTypeDiffersFromTheCas() throws Exception {
        KeyPair caKeys = ec();
        X509CertificateHolder ca = certificate("CN=EC CA", caKeys, "CN=EC CA", caKeys, "SHA256withECDSA", true, false);
        KeyPair responderKeys = rsa();
        X509CertificateHolder responder = certificate("CN=RSA Responder", responderKeys, "CN=EC CA", caKeys,
                "SHA256withECDSA", false, true);
        KeyPair subjectKeys = rsa();
        X509CertificateHolder subject = certificate("CN=Subject", subjectKeys, "CN=EC CA", caKeys,
                "SHA256withECDSA", false, false);

        CertificateID id = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1), ca,
                subject.getSerialNumber());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(responder.getSubject()));
        builder.addResponse(id, CertificateStatus.GOOD);
        BasicOCSPResp basic = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(responderKeys.getPrivate()),
                new X509CertificateHolder[] {responder}, new Date());
        byte[] encoded = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();

        Optional<OcspClient.Answer> answer = new OcspClient(1000).accept(encoded, subject, ca, "test");

        assertThat(answer).isPresent();
        assertThat(answer.get().responder()).isEqualTo(responder);
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509CertificateHolder certificate(String dn, KeyPair keys, String issuer, KeyPair issuerKeys,
                                                     String algorithm, boolean ca, boolean ocspSigning) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86_400_000L), new Date(System.currentTimeMillis() + 86_400_000L),
                new X500Name(dn), keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (ocspSigning) {
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        }
        return builder.build(new JcaContentSignerBuilder(algorithm).build(issuerKeys.getPrivate()));
    }
}
