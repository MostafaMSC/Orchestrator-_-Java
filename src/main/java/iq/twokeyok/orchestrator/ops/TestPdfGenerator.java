package iq.twokeyok.orchestrator.ops;

import java.io.File;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

/**
 * {@code --make-test-pdf <file>} — writes a small, valid, unsigned A4 PDF for
 * the end-to-end signing test.
 *
 * <p>Generating it beats committing a binary: the file is guaranteed to be a
 * well-formed PDF, it carries a timestamp so a signed output can be traced back
 * to the run that produced it, and it leaves plenty of free space on the page
 * for the visible signature.</p>
 */
public final class TestPdfGenerator {

    private TestPdfGenerator() {
    }

    /** @return process exit code */
    public static int generate(String path) {
        File target = new File(path);
        String stamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            try (PDPageContentStream content = new PDPageContentStream(document, page)) {
                write(content, 72, 780, PDType1Font.HELVETICA_BOLD, 16,
                        "TwoKeyOk Orchestrator — end-to-end signing test");
                write(content, 72, 750, PDType1Font.HELVETICA, 11,
                        "This document was generated to exercise the PAdES signing path.");
                write(content, 72, 730, PDType1Font.HELVETICA, 11,
                        "Generated at: " + stamp);
                write(content, 72, 710, PDType1Font.HELVETICA, 11,
                        "It carries no signature until the orchestrator signs it.");
            }

            if (target.getParentFile() != null) {
                target.getParentFile().mkdirs();
            }
            document.save(target);
            System.out.println("Wrote unsigned test document: " + target.getAbsolutePath()
                    + " (" + target.length() + " bytes)");
            return 0;
        } catch (Exception e) {
            System.err.println("Cannot write " + target.getAbsolutePath() + ": " + e.getMessage());
            return 1;
        }
    }

    private static void write(PDPageContentStream content, float x, float y,
                              PDType1Font font, int size, String text) throws java.io.IOException {
        content.beginText();
        content.setFont(font, size);
        content.newLineAtOffset(x, y);
        content.showText(text);
        content.endText();
    }
}
