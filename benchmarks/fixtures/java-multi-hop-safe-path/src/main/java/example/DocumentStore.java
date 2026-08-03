package example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Repository;

@Repository
public final class DocumentStore {
    private final Path contentRoot;

    public DocumentStore(Path contentRoot) throws IOException {
        this.contentRoot = contentRoot.toRealPath();
    }

    public String read(String path) throws IOException {
        Path relative = Path.of(path);
        if (relative.isAbsolute()) {
            throw new SecurityException("Absolute document paths are forbidden");
        }

        Path candidate = contentRoot.resolve(relative).normalize();
        if (!candidate.startsWith(contentRoot)) {
            throw new SecurityException("Document path leaves the content root");
        }

        Path realCandidate = candidate.toRealPath();
        if (!realCandidate.startsWith(contentRoot)) {
            throw new SecurityException("Document link leaves the content root");
        }
        return Files.readString(realCandidate);
    }
}
