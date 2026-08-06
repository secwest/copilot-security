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

    private static String basename(String input) {
        return new File(input).getName();
    }

    public String read(String path) throws IOException {
        String basename = basename(path);
        return Files.readString(contentRoot.resolve(basename).resolve("content.txt"));
    }
}
