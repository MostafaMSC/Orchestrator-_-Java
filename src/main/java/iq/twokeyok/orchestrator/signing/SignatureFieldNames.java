package iq.twokeyok.orchestrator.signing;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iq.twokeyok.orchestrator.signing.SignJob.SignDocument;

/**
 * Chooses the signature field a new signature goes into, so a document that
 * someone has already signed can be signed again.
 *
 * <p>The configured name is used unless a <em>signed</em> field of that name is
 * already in the document - the second signer of a two-signature workflow sends
 * back the first signer's output, which carries {@code signature_field_name}
 * already. The next free name is then taken: {@code Signature2} becomes
 * {@code Signature3}, {@code Approval} becomes {@code Approval2}. An existing
 * <em>empty</em> field of the configured name is still used as it is, which is
 * how a pre-prepared document names where it wants to be signed.</p>
 */
public final class SignatureFieldNames {

    private static final Logger log = LoggerFactory.getLogger(SignatureFieldNames.class);
    private static final Pattern TRAILING_NUMBER = Pattern.compile("^(.*?)(\\d+)$");

    private SignatureFieldNames() {
    }

    /** A name that is free, or an empty signature field, in every document of the request. */
    public static String choose(String configured, List<SignDocument> documents) {
        Set<String> signed = new HashSet<>();
        Set<String> all = new HashSet<>();
        for (SignDocument document : documents) {
            collect(document.content(), signed, all);
        }
        if (!signed.contains(configured)) {
            return configured;
        }

        Matcher numbered = TRAILING_NUMBER.matcher(configured);
        String base = numbered.matches() ? numbered.group(1) : configured;
        int next = numbered.matches() ? Integer.parseInt(numbered.group(2)) + 1 : 2;
        while (all.contains(base + next)) {
            next++;
        }
        String chosen = base + next;
        log.info("Signature field '{}' is already signed in the document; this signature goes into '{}'",
                configured, chosen);
        return chosen;
    }

    private static void collect(byte[] pdf, Set<String> signed, Set<String> all) {
        try (PDDocument document = PDDocument.load(pdf)) {
            PDAcroForm form = document.getDocumentCatalog().getAcroForm();
            if (form == null) {
                return;
            }
            for (PDField field : form.getFieldTree()) {
                String name = field.getFullyQualifiedName();
                all.add(name);
                if (field instanceof PDSignatureField signature && signature.getSignature() != null) {
                    signed.add(name);
                }
            }
        } catch (Exception e) {
            // Unreadable here means unreadable for the signing engine too; that
            // reports it properly, so the configured name is simply kept.
            log.debug("Cannot read the signature fields of a document: {}", e.getMessage());
        }
    }
}
