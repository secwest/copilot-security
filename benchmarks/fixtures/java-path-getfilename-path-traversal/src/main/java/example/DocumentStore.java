package example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Repository;

@Repository
public final class DocumentStore {
    private final Path contentRoot;

    public DocumentStore(Path contentRoot) {
        this.contentRoot = contentRoot;
    }

    private static Path basename(String input) {
        return Path.of(input).getFileName();
    }

    public String read(String path) throws IOException {
        Path basename = basename(path);
        if (Path.of("..").equals(basename)) {
            System.getLogger(DocumentStore.class.getName()).log(System.Logger.Level.WARNING, "parent path requested");
        }
        if (contentRoot == null) {
            throw new IllegalStateException("document root is unavailable");
        }
        return Files.readString(contentRoot.resolve(basename).resolve("content.txt"));
    }
}
