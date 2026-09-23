package iq.twokeyok.orchestrator.appearance;

import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;
import iq.twokeyok.orchestrator.appearance.AppearanceXmlWriter.LabelOverride;
import iq.twokeyok.orchestrator.appearance.ResolvedAppearance.SignatureBox;
import iq.twokeyok.orchestrator.error.ErrorCode;
import iq.twokeyok.orchestrator.error.OrchestratorException;
import iq.twokeyok.orchestrator.web.dto.SignatureAppearanceRequest;

/**
 * Serves the appearance catalogue and merges a request's
 * {@code signature_appearance} onto the selected template.
 *
 * <p>Precedence for every value is: request (only where the client is allowed to
 * override) → configured signer/client default → template default.</p>
 */
@Service
public class AppearanceService {

    private final AppearanceRepository repository;
    private final AppearanceXmlWriter xmlWriter;

    public AppearanceService(AppearanceRepository repository, AppearanceXmlWriter xmlWriter) {
        this.repository = repository;
        this.xmlWriter = xmlWriter;
    }

    public Collection<AppearanceTemplate> list() {
        return repository.findAll();
    }

    public AppearanceTemplate get(String templateId) {
        return repository.findById(templateId)
                .orElseThrow(() -> new OrchestratorException(ErrorCode.APPEARANCE_NOT_FOUND, templateId));
    }

    /**
     * @param defaultTemplateId    template chosen by configuration
     * @param request              the caller's {@code signature_appearance}, may be {@code null}
     * @param defaults             text values fixed by the signer / client configuration
     * @param allowRequestValues   may the request change text, images and placement?
     * @param allowRequestTemplate may the request pick a different template?
     */
    public ResolvedAppearance resolve(String defaultTemplateId,
                                      SignatureAppearanceRequest request,
                                      TextDefaults defaults,
                                      boolean allowRequestValues,
                                      boolean allowRequestTemplate) {

        String requestedTemplate = request == null ? null : request.templateId();
        if (requestedTemplate != null && !requestedTemplate.isBlank() && !allowRequestTemplate) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_ALLOWED);
        }
        if (request != null && carriesValues(request) && !allowRequestValues) {
            throw new OrchestratorException(ErrorCode.APPEARANCE_NOT_ALLOWED);
        }

        if (!repository.isEnabled()) {
            // appearance.enabled=false means "sign, but draw nothing".
            return null;
        }

        String templateId = (allowRequestTemplate && requestedTemplate != null && !requestedTemplate.isBlank())
                ? requestedTemplate
                : defaultTemplateId;
        AppearanceTemplate template = (templateId == null || templateId.isBlank())
                ? repository.findDefault().orElseThrow(
                        () -> new OrchestratorException(ErrorCode.APPEARANCE_NOT_FOUND, "<default>"))
                : get(templateId);

        SignatureAppearanceRequest effective = allowRequestValues ? request : null;

        Map<String, String> values = new LinkedHashMap<>();
        Map<String, LabelOverride> labels = new LinkedHashMap<>();

        put(values, labels, template, Fields.SIGNED_BY,
                effective == null ? null : effective.signedBy(), defaults.signedBy());
        put(values, labels, template, Fields.REASON,
                effective == null ? null : effective.reason(), defaults.reason());
        put(values, labels, template, Fields.LOCATION,
                effective == null ? null : effective.location(), defaults.location());
        put(values, labels, template, Fields.CONTACT_INFO,
                effective == null ? null : effective.contactInfo(), defaults.contactInfo());
        put(values, labels, template, Fields.SIGNING_DATE,
                effective == null ? null : effective.signingDate(), null);

        String companyLogo = image(effective == null ? null : effective.companyLogo(),
                templateValue(template, Fields.COMPANY_LOGO));
        String handSignature = image(effective == null ? null : effective.handSignature(),
                templateValue(template, Fields.HAND_SIGNATURE));
        values.put(Fields.COMPANY_LOGO, companyLogo);
        values.put(Fields.HAND_SIGNATURE, handSignature);

        byte[] appearanceXml = xmlWriter.write(template, values, labels);

        // Images already embedded in the appearance document must not also be set
        // on the request, or ADSS renders them twice.
        boolean logoEmbedded = isEmbedded(template, Fields.COMPANY_LOGO, companyLogo);
        boolean handEmbedded = isEmbedded(template, Fields.HAND_SIGNATURE, handSignature);

        String signerRole = firstNonBlank(
                effective == null || effective.signerRole() == null ? null : effective.signerRole().value(),
                defaults.signerRole(),
                templateValue(template, Fields.SIGNER_ROLE));

        return new ResolvedAppearance(
                template.templateId(),
                appearanceXml,
                values.get(Fields.SIGNED_BY),
                signerRole,
                values.get(Fields.REASON),
                values.get(Fields.LOCATION),
                values.get(Fields.CONTACT_INFO),
                logoEmbedded ? null : decode(companyLogo),
                handEmbedded ? null : decode(handSignature),
                box(effective, template));
    }

    private static boolean isEmbedded(AppearanceTemplate template, String key, String value) {
        AppearanceTemplate.Field field = template.fields().get(key);
        return field != null && field.included() && value != null && !value.isBlank();
    }

    private static void put(Map<String, String> values,
                            Map<String, LabelOverride> labels,
                            AppearanceTemplate template,
                            String key,
                            SignatureAppearanceRequest.TextField requested,
                            String configuredDefault) {
        String value = firstNonBlank(
                requested == null ? null : requested.value(),
                configuredDefault,
                templateValue(template, key));
        values.put(key, value);
        if (requested != null && (requested.label() != null || requested.includeLabel() != null)) {
            labels.put(key, new LabelOverride(requested.label(), requested.includeLabel()));
        }
    }

    private static String templateValue(AppearanceTemplate template, String key) {
        AppearanceTemplate.Field field = template.fields().get(key);
        return field == null ? null : field.value();
    }

    private static String image(SignatureAppearanceRequest.Image requested, String templateValue) {
        String value = firstNonBlank(requested == null ? null : requested.value(), templateValue);
        if (value != null && !value.isBlank()) {
            decode(value); // fail fast on malformed Base64
        }
        return value;
    }

    private static byte[] decode(String base64) {
        if (base64 == null || base64.isBlank()) {
            return null;
        }
        try {
            return Base64.getMimeDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new OrchestratorException(ErrorCode.INVALID_APPEARANCE, e);
        }
    }

    private static SignatureBox box(SignatureAppearanceRequest request, AppearanceTemplate template) {
        if (request != null && request.signatureField() != null && request.signatureField().complete()) {
            SignatureAppearanceRequest.Box b = request.signatureField();
            return new SignatureBox(b.x(), b.y(), b.width(), b.height(),
                    b.pageNo() == null ? 1 : b.pageNo());
        }
        AppearanceTemplate.Box b = template.signatureField();
        if (b != null && b.x() != null && b.y() != null && b.width() != null && b.height() != null) {
            return new SignatureBox(b.x(), b.y(), b.width(), b.height(),
                    b.pageNo() == null ? 1 : b.pageNo());
        }
        return null;
    }

    private static boolean carriesValues(SignatureAppearanceRequest request) {
        return request.signedBy() != null
                || request.signerRole() != null
                || request.signingDate() != null
                || request.reason() != null
                || request.location() != null
                || request.contactInfo() != null
                || request.textFont() != null
                || request.backgroundColor() != null
                || request.signatureField() != null
                || request.companyLogo() != null
                || request.handSignature() != null;
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return null;
    }

    /** Text values fixed by the signer or client configuration. */
    public record TextDefaults(String signedBy,
                               String signerRole,
                               String reason,
                               String location,
                               String contactInfo) {

        public static final TextDefaults EMPTY = new TextDefaults(null, null, null, null, null);
    }
}
