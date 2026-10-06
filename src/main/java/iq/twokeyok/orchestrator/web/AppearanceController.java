package iq.twokeyok.orchestrator.web;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import iq.twokeyok.orchestrator.appearance.AppearanceService;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate;
import iq.twokeyok.orchestrator.web.dto.AppearanceTemplateView;

/**
 * Signature appearance templates — the catalogue a business application picks
 * from, and then names in {@code signature_appearance.template_id} when it calls
 * {@code /service/sign}.
 *
 * <pre>
 * GET    /service/signing/appearances/list          List Signature Appearances
 * GET    /service/signing/appearances/{template_id} Get Signature Appearance by ID
 * POST   /service/signing/appearances               Create or Update
 * DELETE /service/signing/appearances/{template_id} Delete
 * </pre>
 *
 * <p>Create and update share one {@code POST}, as the API guide describes them:
 * the response distinguishes the two, {@code 201} for a template that did not
 * exist and {@code 200} for one that did. {@code PUT} is accepted as well, since
 * that is the more usual verb for an update and costs nothing to allow.</p>
 *
 * <p>Templates declared in {@code orchestrator.yml} are visible here but cannot
 * be changed or deleted through the API — that file belongs to whoever operates
 * the service, and a write here would be silently undone at the next restart.
 * Only templates in the appearance store are managed.</p>
 */
@RestController
@RequestMapping("/service/signing/appearances")
public class AppearanceController {

    private final AppearanceService appearanceService;

    public AppearanceController(AppearanceService appearanceService) {
        this.appearanceService = appearanceService;
    }

    @GetMapping(path = "/list", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<AppearanceTemplateView> list() {
        return appearanceService.list().stream()
                .map(AppearanceTemplateView::of)
                .toList();
    }

    @GetMapping(path = "/{templateId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public AppearanceTemplate get(@PathVariable("templateId") String templateId) {
        return appearanceService.get(templateId);
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppearanceTemplate> createOrUpdate(@RequestBody AppearanceTemplate template) {
        AppearanceService.Saved saved = appearanceService.save(template);
        return ResponseEntity.status(saved.created() ? HttpStatus.CREATED : HttpStatus.OK)
                .body(saved.template());
    }

    @PutMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppearanceTemplate> update(@RequestBody AppearanceTemplate template) {
        return createOrUpdate(template);
    }

    @DeleteMapping(path = "/{templateId}")
    public ResponseEntity<Void> delete(@PathVariable("templateId") String templateId) {
        appearanceService.delete(templateId);
        return ResponseEntity.noContent().build();
    }
}
