package iq.twokeyok.orchestrator.web;

import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import iq.twokeyok.orchestrator.appearance.AppearanceService;
import iq.twokeyok.orchestrator.web.dto.AppearanceTemplateView;

/**
 * {@code GET /orchestrator/service/signing/appearances/list} — List Signature
 * Appearances.
 *
 * <p>Returns the appearance templates a business application may reference from
 * {@code signature_appearance.template_id} when it calls {@code /service/sign}.</p>
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
}
