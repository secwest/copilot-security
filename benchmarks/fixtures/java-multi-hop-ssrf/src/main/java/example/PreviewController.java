package example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/previews")
public final class PreviewController {
    private final PreviewService previews;

    public PreviewController(PreviewService previews) {
        this.previews = previews;
    }

    @GetMapping
    public String get(@RequestParam String target) throws Exception {
        return previews.fetch(target);
    }
}
