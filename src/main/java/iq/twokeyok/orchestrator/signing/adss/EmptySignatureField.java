package iq.twokeyok.orchestrator.signing.adss;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import iq.twokeyok.orchestrator.appearance.ResolvedAppearance.SignatureBox;

/**
 * Appends an empty signature field to a document that is already signed, so
 * the ADSS SDK can sign into it without disturbing the signatures before it.
 *
 * <p>Asked to create the field itself ({@code addEmptySignatureFieldPosition})
 * on a signed document, the SDK writes the whole file out again: the earlier
 * signatures' byte ranges no longer match and their contents are mangled, so
 * the first signer's signature is destroyed. Given a field that already exists,
 * it appends instead - every earlier byte kept - which is what a second signer
 * needs. The field is added here as an incremental update for that reason.</p>
 */
final class EmptySignatureField {

    private EmptySignatureField() {
    }

    /** Whether the document carries at least one signature already. */
    static boolean isSigned(byte[] pdf) {
        try (PDDocument document = PDDocument.load(pdf)) {
            return !document.getSignatureDictionaries().isEmpty();
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * @return the document with an empty signature field {@code name} on
     *         {@code box}, appended as an incremental update; the document as it
     *         is when a field of that name exists already
     */
    static byte[] append(byte[] pdf, String name, SignatureBox box) throws IOException {
        try (PDDocument document = PDDocument.load(pdf)) {
            PDAcroForm form = document.getDocumentCatalog().getAcroForm();
            if (form == null) {
                form = new PDAcroForm(document);
                document.getDocumentCatalog().setAcroForm(form);
            }
            for (PDField existing : form.getFieldTree()) {
                if (name.equals(existing.getFullyQualifiedName())) {
                    return pdf;
                }
            }
            int pageIndex = Math.max(1, Math.min(box.pageNo(), document.getNumberOfPages())) - 1;
            PDPage page = document.getPage(pageIndex);

            PDSignatureField field = new PDSignatureField(form);
            field.setPartialName(name);
            PDAnnotationWidget widget = field.getWidgets().get(0);
            widget.setRectangle(new PDRectangle(box.x(), box.y(), box.width(), box.height()));
            widget.setPage(page);
            widget.setPrinted(true);

            // getAnnotations() and getFields() return copies in PDFBox 2; the
            // underlying arrays are what an incremental save writes.
            COSArray annotations = arrayIn(page.getCOSObject(), COSName.ANNOTS);
            annotations.add(widget.getCOSObject());
            COSArray fields = arrayIn(form.getCOSObject(), COSName.FIELDS);
            fields.add(field.getCOSObject());
            form.getCOSObject().setInt(COSName.getPDFName("SigFlags"), 3);

            document.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
            form.getCOSObject().setNeedToBeUpdated(true);
            fields.setNeedToBeUpdated(true);
            page.getCOSObject().setNeedToBeUpdated(true);
            annotations.setNeedToBeUpdated(true);
            field.getCOSObject().setNeedToBeUpdated(true);

            ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + 4096);
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    private static COSArray arrayIn(COSDictionary dictionary, COSName key) {
        COSBase existing = dictionary.getDictionaryObject(key);
        if (existing instanceof COSArray array) {
            return array;
        }
        COSArray array = new COSArray();
        dictionary.setItem(key, array);
        return array;
    }
}
