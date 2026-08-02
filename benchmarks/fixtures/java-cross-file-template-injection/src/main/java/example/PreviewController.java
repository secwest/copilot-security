package example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class PreviewController {
    private final TemplateRenderer renderer;

    public PreviewController(TemplateRenderer renderer) {
        this.renderer = renderer;
    }

    @PostMapping("/preview")
    public String preview(@RequestParam String template) {
        return renderer.render(template);
    }
}
