package iq.twokeyok.orchestrator.signing;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult.SignedDocument;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContainerPackagerTest {

    private final ContainerPackager packager = new ContainerPackager();

    private static SignedDocument document(String name, String content) {
        return new SignedDocument(name, content.getBytes(StandardCharsets.UTF_8));
    }

    private static List<String> entryNames(byte[] archive) throws Exception {
        List<String> names = new ArrayList<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                names.add(entry.getName());
            }
        }
        return names;
    }

    @Test
    void returnsASingleDocumentAsPdf() {
        ContainerPackager.Payload payload =
                packager.pack(List.of(document("invoice.pdf", "%PDF-1.7")), "NONE");

        assertThat(payload.contentType()).isEqualTo("application/pdf");
        assertThat(payload.fileName()).isEqualTo("invoice.pdf");
        assertThat(payload.content()).isEqualTo("%PDF-1.7".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void zipsSeveralDocuments() throws Exception {
        ContainerPackager.Payload payload = packager.pack(
                List.of(document("a.pdf", "one"), document("b.pdf", "two")), "NONE");

        assertThat(payload.contentType()).isEqualTo("application/zip");
        assertThat(entryNames(payload.content())).containsExactly("a.pdf", "b.pdf");
    }

    @Test
    void makesDuplicateFileNamesUnique() throws Exception {
        ContainerPackager.Payload payload = packager.pack(
                List.of(document("report.pdf", "one"), document("report.pdf", "two")), "NONE");

        assertThat(entryNames(payload.content())).containsExactly("report.pdf", "report-2.pdf");
    }

    @Test
    void writesTheAsicMimetypeAsTheFirstEntry() throws Exception {
        ContainerPackager.Payload payload =
                packager.pack(List.of(document("a.pdf", "one")), "ASiC-E");

        assertThat(payload.contentType()).isEqualTo("application/vnd.etsi.asic-e+zip");
        assertThat(payload.fileName()).isEqualTo("signed-documents.asice");
        assertThat(entryNames(payload.content())).containsExactly("mimetype", "a.pdf");
    }

    @Test
    void rejectsTimestampedAndUnknownContainers() {
        assertThatThrownBy(() -> packager.pack(List.of(document("a.pdf", "one")), "ASiC-S/T"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.UNSUPPORTED_CONTAINER);

        assertThatThrownBy(() -> packager.pack(List.of(document("a.pdf", "one")), "CADES"))
                .isInstanceOf(OrchestratorException.class)
                .extracting(e -> ((OrchestratorException) e).errorCode())
                .isEqualTo(ErrorCode.UNSUPPORTED_CONTAINER);
    }
}
