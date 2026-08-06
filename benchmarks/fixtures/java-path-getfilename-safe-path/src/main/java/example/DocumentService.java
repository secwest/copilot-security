package example;

import java.io.IOException;
import org.springframework.stereotype.Service;

@Service
public final class DocumentService {
    private final DocumentStore store;

    public DocumentService(DocumentStore store) {
        this.store = store;
    }

    public String read(String path) throws IOException {
        return store.read(path);
    }
}
