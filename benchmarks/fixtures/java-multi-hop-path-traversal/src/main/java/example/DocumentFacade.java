package example;

import java.io.IOException;
import org.springframework.stereotype.Service;

@Service
public final class DocumentFacade {
    private final DocumentService service;

    public DocumentFacade(DocumentService service) {
        this.service = service;
    }

    public String read(String path) throws IOException {
        return service.read(path);
    }
}
