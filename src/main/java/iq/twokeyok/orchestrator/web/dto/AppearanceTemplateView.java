package iq.twokeyok.orchestrator.web.dto;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate;

/**
 * The public view of an appearance template returned by
 * {@code GET /service/signing/appearances/list}.
 *
 * <p>It is the stored template minus the embedded image payloads: a default logo
 * or handwritten signature can be hundreds of kilobytes of Base64 that no caller
 * needs in order to choose a template, so the view reports only that an image is
 * present.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AppearanceTemplateView(
        String templateId,
        String name,
        String description,
        Integer width,
        Integer height,
        AppearanceTemplate.Box signatureField,
        Map<String, FieldView> fields) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FieldView(boolean include,
                            String label,
                            boolean showLabel,
                            String value,
                            Boolean hasImage,
                            AppearanceTemplate.Box position) {
    }

    public static AppearanceTemplateView of(AppearanceTemplate template) {
        Map<String, FieldView> fields = new LinkedHashMap<>();
        template.fields().forEach((key, field) -> {
            boolean image = AppearanceTemplate.Fields.COMPANY_LOGO.equals(key)
                    || AppearanceTemplate.Fields.HAND_SIGNATURE.equals(key);
            boolean hasValue = field.value() != null && !field.value().isBlank();
            fields.put(key, new FieldView(
                    field.included(),
                    field.label(),
                    field.labelShown(),
                    image ? null : field.value(),
                    image ? hasValue : null,
                    field.position()));
        });
        return new AppearanceTemplateView(
                template.templateId(),
                template.name(),
                template.description(),
                template.width(),
                template.height(),
                template.signatureField(),
                fields);
    }
}
