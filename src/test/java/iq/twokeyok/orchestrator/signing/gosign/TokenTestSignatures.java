package iq.twokeyok.orchestrator.signing.gosign;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;

import iq.twokeyok.orchestrator.appearance.ResolvedAppearance.SignatureBox;
import iq.twokeyok.orchestrator.signing.adss.EmptySignatureField;

/**
 * Stands in for the token in tests: a key generated here signs the digest the
 * orchestrator produced, the way an eToken would.
 *
 * <p>It proves the two halves fit together and nothing more. A key made in this
 * JVM cannot show what the Go>Sign Service returns, what a PKCS#11 driver puts
 * in a CMS, or that profile 007 behaves as its snippet suggests, so passing
 * tests here are not evidence the feature works against a real token.</p>
 */
public final class TokenTestSignatures {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private TokenTestSignatures() {
    }

    /** A one-page document to prepare for signing. */
    public static byte[] blankPdf() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage(PDRectangle.A4));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    /** A document with an empty signature field, as {@code prepare} receives it. */
    public static byte[] withField(String fieldName) throws Exception {
        return EmptySignatureField.append(blankPdf(), fieldName,
                new SignatureBox(50, 160, 200, 80, 1));
    }

    public static DeferredPdfSignature.Prepared prepared(String fieldName) throws Exception {
        return DeferredPdfSignature.prepare(withField(fieldName), fieldName,
                "ETSI.CAdES.detached", "SHA256", 20000,
                new DeferredPdfSignature.SignatureMetadata("Test Signer", "Unit test", "Baghdad", null));
    }

    /** A detached CMS over exactly the bytes {@code prepared} covers. */
    public static byte[] cmsOver(DeferredPdfSignature.Prepared prepared) throws Exception {
        return cmsOver(DeferredPdfSignature.covered(prepared.pdf()));
    }

    public static byte[] cmsOver(byte[] content) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Name dn = new X500Name("CN=Token Under Test,O=TwoKeyOk");
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                new JcaX509v3CertificateBuilder(dn, BigInteger.ONE,
                        new Date(System.currentTimeMillis() - 86_400_000L),
                        new Date(System.currentTimeMillis() + 86_400_000L), dn, pair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC")
                                .build(pair.getPrivate())));

        CMSSignedDataGenerator cms = new CMSSignedDataGenerator();
        cms.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(pair.getPrivate()),
                        certificate));
        cms.addCertificates(new CollectionStore<>(List.of(new JcaX509CertificateHolder(certificate))));
        return cms.generate(new CMSProcessableByteArray(content), false).getEncoded();
    }
}
