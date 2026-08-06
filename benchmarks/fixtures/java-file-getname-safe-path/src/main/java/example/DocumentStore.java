package example;

import java.io.File;
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

    public String read(String path) throws IOException {
        String basename = new File(path).getName();
        if ("..".equals(basename)) {
            throw new SecurityException("parent path components are forbidden");
        }
        return Files.readString(contentRoot.resolve(basename).resolve("content.txt"));
    }
}
