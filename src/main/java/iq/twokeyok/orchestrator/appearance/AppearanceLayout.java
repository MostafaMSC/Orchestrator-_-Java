package iq.twokeyok.orchestrator.appearance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Box;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Field;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Font;
import iq.twokeyok.orchestrator.config.SigningProperties;
import iq.twokeyok.orchestrator.config.SigningProperties.AppearanceTemplateConfig;
import iq.twokeyok.orchestrator.config.SigningProperties.TextField;

/**
 * Turns an appearance declared in {@code signing.dss.signature.appearance.appearances}
 * into the positioned template the ADSS appearance document needs.
 *
 * <p>The configuration format says <em>what</em> to show and, through
 * {@code signature_text_position}, roughly where — it does not position each
 * line. The ADSS {@code SignatureAppearanceSettings} document does need a box
 * per field, so this class lays the text out: the enabled text fields are
 * stacked in a fixed reading order, and the image sits above, below or beside
 * them.</p>
 *
 * <p>A template that needs pixel-exact placement is better written as a JSON file
 * in the appearance store, where every field carries its own position.</p>
 */
public final class AppearanceLayout {

    private static final Logger log = LoggerFactory.getLogger(AppearanceLayout.class);

    /**
     * Reading order of the text lines inside the appearance. {@code signer_role}
     * is absent on purpose — the ADSS appearance document has no role field, so
     * allocating a line for it would shift every other line down for nothing.
     */
    private static final List<String> TEXT_ORDER = List.of(
            Fields.SIGNED_BY,
            Fields.SIGNING_DATE,
            Fields.REASON,
            Fields.LOCATION,
            Fields.CONTACT_INFO);

    private static final int PADDING = 4;
    private static final double LINE_SPACING = 1.4;

    private AppearanceLayout() {
    }

    /**
     * @param config    the configured template
     * @param configDir directory relative image paths are resolved against
     */
    public static AppearanceTemplate toTemplate(AppearanceTemplateConfig config, Path configDir) {
        int width = config.signatureField() != null && config.signatureField().width() > 0
                ? config.signatureField().width() : 200;
        int height = config.signatureField() != null && config.signatureField().height() > 0
                ? config.signatureField().height() : 80;

        Font font = font(config.textFont());
        Map<String, TextField> text = textFields(config);
        String logo = loadImage(config.companyLogo(), configDir, config.templateId(), "company_logo");
        String hand = loadImage(config.handSignature(), configDir, config.templateId(), "hand_signature");
        boolean hasImage = logo != null || hand != null;

        Regions regions = split(config.signatureTextPosition(), width, height, hasImage);

        Map<String, Field> fields = new LinkedHashMap<>();
        layoutText(fields, text, regions.text(), font);
        // Carried without a position: consumed as the signature's signer role.
        if (config.signerRole() != null) {
            fields.put(Fields.SIGNER_ROLE, new Field(true, config.signerRole().label(),
                    config.signerRole().includeLabel(), config.signerRole().value(), null, null, null));
        }
        if (logo != null) {
            fields.put(Fields.COMPANY_LOGO, imageField("Company Logo", logo, regions.image(),
                    imageName(config.companyLogo(), "company-logo.png")));
        }
        if (hand != null) {
            fields.put(Fields.HAND_SIGNATURE, imageField("Hand Signature", hand, regions.image(),
                    imageName(config.handSignature(), "hand-signature.png")));
        }

        return new AppearanceTemplate(
                config.templateId(),
                config.name() == null ? config.templateId() : config.name(),
                config.description(),
                config.enabled(),
                width,
                height,
                null,
                color(config.textBackgroundColor()),
                font,
                box(config.signatureField(), width, height),
                fields);
    }

    // ------------------------------------------------------------------ text --

    private static Map<String, TextField> textFields(AppearanceTemplateConfig config) {
        Map<String, TextField> text = new LinkedHashMap<>();
        put(text, Fields.SIGNED_BY, config.signedBy());
        put(text, Fields.SIGNING_DATE, config.signingDate());
        put(text, Fields.REASON, config.reason());
        put(text, Fields.LOCATION, config.location());
        put(text, Fields.CONTACT_INFO, config.contactInfo());
        return text;
    }

    private static void put(Map<String, TextField> target, String key, TextField field) {
        if (field != null) {
            target.put(key, field);
        }
    }

    /** Stacks the configured lines top-down inside the text region. */
    private static void layoutText(Map<String, Field> fields,
                                   Map<String, TextField> text,
                                   Box region,
                                   Font font) {
        int lineHeight = (int) Math.ceil(font.fontSize() * LINE_SPACING);
        int y = region.y();
        for (String key : TEXT_ORDER) {
            TextField configured = text.get(key);
            if (configured == null) {
                continue;
            }
            fields.put(key, new Field(
                    true,
                    configured.label(),
                    configured.includeLabel(),
                    configured.value(),
                    new Box(region.x(), y, region.width(), lineHeight, null),
                    null,
                    null));
            y += lineHeight;
        }
        if (y > region.y() + region.height()) {
            log.warn("Appearance text needs {} pt but only {} pt are available; "
                            + "increase signature_field.height or reduce text_font.size",
                    y - region.y(), region.height());
        }
    }

    private static Field imageField(String label, String base64, Box region, String imageName) {
        return new Field(true, label, false, base64, region, null, imageName);
    }

    // ----------------------------------------------------------------- layout --

    /** The text and image halves of the appearance box. */
    private record Regions(Box text, Box image) {
    }

    private static Regions split(String position, int width, int height, boolean hasImage) {
        int innerX = PADDING;
        int innerY = PADDING;
        int innerW = Math.max(1, width - 2 * PADDING);
        int innerH = Math.max(1, height - 2 * PADDING);

        if (!hasImage) {
            Box all = new Box(innerX, innerY, innerW, innerH, null);
            return new Regions(all, all);
        }

        String where = position == null ? "BOTTOM" : position.trim().toUpperCase(Locale.ROOT);
        return switch (where) {
            case "TOP" -> new Regions(
                    new Box(innerX, innerY, innerW, innerH / 2, null),
                    new Box(innerX, innerY + innerH / 2, innerW, innerH / 2, null));
            case "LEFT" -> new Regions(
                    new Box(innerX, innerY, innerW / 2, innerH, null),
                    new Box(innerX + innerW / 2, innerY, innerW / 2, innerH, null));
            case "RIGHT" -> new Regions(
                    new Box(innerX + innerW / 2, innerY, innerW / 2, innerH, null),
                    new Box(innerX, innerY, innerW / 2, innerH, null));
            // BOTTOM is the reference default: image on top, text underneath.
            default -> new Regions(
                    new Box(innerX, innerY + innerH / 2, innerW, innerH / 2, null),
                    new Box(innerX, innerY, innerW, innerH / 2, null));
        };
    }

    // ----------------------------------------------------------------- images --

    /**
     * Configuration gives an image as a file path; a request gives it as Base64.
     * Both end up as Base64 in the template, read once at start-up.
     */
    private static String loadImage(SigningProperties.Image image,
                                    Path configDir,
                                    String templateId,
                                    String field) {
        if (image == null || image.value() == null || image.value().isBlank()) {
            return null;
        }
        String value = image.value().trim();
        if (looksLikeBase64(value)) {
            return value;
        }
        Path path = Path.of(value);
        if (!path.isAbsolute() && configDir != null) {
            path = configDir.resolve(value);
        }
        try {
            return Base64.getEncoder().encodeToString(Files.readAllBytes(path));
        } catch (IOException e) {
            // A missing logo must not stop the service, but it must be loud: the
            // signature will be produced without it.
            log.error("Appearance '{}' field '{}': cannot read image {} ({}). "
                            + "Signatures from this template will have no image.",
                    templateId, field, path, e.getMessage());
            return null;
        }
    }

    /** A path has an extension and no Base64 padding; anything long and opaque is data. */
    private static boolean looksLikeBase64(String value) {
        if (value.length() < 128) {
            return false;
        }
        return value.chars().allMatch(c ->
                Character.isLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || Character.isWhitespace(c));
    }

    private static String imageName(SigningProperties.Image image, String fallback) {
        if (image == null || image.name() == null || image.name().isBlank()) {
            if (image != null && image.value() != null && !looksLikeBase64(image.value())) {
                return Path.of(image.value()).getFileName().toString();
            }
            return fallback;
        }
        return image.name();
    }

    // ---------------------------------------------------------------- helpers --

    private static Font font(SigningProperties.Font configured) {
        if (configured == null) {
            return new Font("Helvetica", 10, null);
        }
        return new Font(configured.name(), configured.size(), color(configured.color()));
    }

    private static AppearanceTemplate.Color color(SigningProperties.Color configured) {
        return configured == null ? null
                : new AppearanceTemplate.Color(configured.r(), configured.g(), configured.b(), configured.a());
    }

    private static Box box(SigningProperties.SignatureField field, int width, int height) {
        if (field == null || !field.placed()) {
            return null;
        }
        return new Box(field.x(), field.y(), width, height, field.pageNo());
    }

    /** Field ids configured on the appearance, so the caller need not repeat them. */
    public static List<String> textOrder() {
        return new ArrayList<>(TEXT_ORDER);
    }
}
