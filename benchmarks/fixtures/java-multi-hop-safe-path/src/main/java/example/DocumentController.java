package example;

import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class DocumentController {
    private final DocumentFacade documents;

    public DocumentController(DocumentFacade documents) {
        this.documents = documents;
    }

    @GetMapping("/documents")
    public String read(@RequestParam String path) throws IOException {
        return documents.read(path);
    }
}
