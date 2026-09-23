package iq.twokeyok.orchestrator.signing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.springframework.stereotype.Component;

import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.signing.SignJob.SignResult.SignedDocument;

/**
 * Turns the signed documents into the payload the caller receives.
 *
 * <p>With {@code container_type=NONE} a single document is returned as-is and
 * several documents are returned as a plain zip, which is what the TwoKeyOk
 * MiddleWare guide describes. {@code ASiC-S} and {@code ASiC-E} wrap the same
 * documents in an ETSI EN 319 162 container.</p>
 *
 * <p>The timestamped variants {@code ASiC-S/T} and {@code ASiC-E/T} need a
 * container-level timestamp token and are rejected rather than silently
 * downgraded.</p>
 */
@Component
public class ContainerPackager {

    private static final String ASIC_S_MIMETYPE = "application/vnd.etsi.asic-s+zip";
    private static final String ASIC_E_MIMETYPE = "application/vnd.etsi.asic-e+zip";

    /**
     * @param content     bytes to return
     * @param fileName    file name for the {@code Content-Disposition} header
     * @param contentType media type of the payload
     */
    public record Payload(byte[] content, String fileName, String contentType) {
    }

    public Payload pack(List<SignedDocument> documents, String containerType) {
        String container = containerType == null ? "NONE" : containerType.trim().toUpperCase(Locale.ROOT);
        return switch (container) {
            case "", "NONE" -> plain(documents);
            case "ASIC-S" -> asic(documents, ASIC_S_MIMETYPE, "signed-documents.asics");
            case "ASIC-E" -> asic(documents, ASIC_E_MIMETYPE, "signed-documents.asice");
            case "ASIC-S/T", "ASIC-E/T" ->
                    throw new OrchestratorException(ErrorCode.UNSUPPORTED_CONTAINER, containerType);
            default -> throw new OrchestratorException(ErrorCode.UNSUPPORTED_CONTAINER, containerType);
        };
    }

    private static Payload plain(List<SignedDocument> documents) {
        if (documents.size() == 1) {
            SignedDocument only = documents.get(0);
            return new Payload(only.content(), only.fileName(), "application/pdf");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(buffer, StandardCharsets.UTF_8)) {
            writeDocuments(zip, documents);
        } catch (IOException e) {
            throw new OrchestratorException(ErrorCode.INTERNAL_ERROR, e);
        }
        return new Payload(buffer.toByteArray(), "signed-documents.zip", "application/zip");
    }

    private static Payload asic(List<SignedDocument> documents, String mimetype, String fileName) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(buffer, StandardCharsets.UTF_8)) {
            writeMimetype(zip, mimetype);
            writeDocuments(zip, documents);
        } catch (IOException e) {
            throw new OrchestratorException(ErrorCode.INTERNAL_ERROR, e);
        }
        return new Payload(buffer.toByteArray(), fileName, mimetype);
    }

    /** ASiC requires {@code mimetype} to be the first entry, uncompressed. */
    private static void writeMimetype(ZipOutputStream zip, String mimetype) throws IOException {
        byte[] bytes = mimetype.getBytes(StandardCharsets.US_ASCII);
        ZipEntry entry = new ZipEntry("mimetype");
        entry.setMethod(ZipEntry.STORED);
        entry.setSize(bytes.length);
        entry.setCompressedSize(bytes.length);
        CRC32 crc = new CRC32();
        crc.update(bytes);
        entry.setCrc(crc.getValue());
        zip.putNextEntry(entry);
        zip.write(bytes);
        zip.closeEntry();
        zip.setMethod(ZipOutputStream.DEFLATED);
    }

    private static void writeDocuments(ZipOutputStream zip, List<SignedDocument> documents) throws IOException {
        java.util.Set<String> used = new java.util.HashSet<>();
        int index = 0;
        for (SignedDocument document : documents) {
            index++;
            String name = document.fileName() == null || document.fileName().isBlank()
                    ? "signed-" + index + ".pdf"
                    : document.fileName();
            // Two uploads may carry the same file name; a zip entry may not.
            if (!used.add(name)) {
                int dot = name.lastIndexOf('.');
                name = dot > 0
                        ? name.substring(0, dot) + "-" + index + name.substring(dot)
                        : name + "-" + index;
                used.add(name);
            }
            zip.putNextEntry(new ZipEntry(name));
            zip.write(document.content());
            zip.closeEntry();
        }
    }
}
