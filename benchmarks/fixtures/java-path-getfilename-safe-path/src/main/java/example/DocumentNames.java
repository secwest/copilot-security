package example;

import java.nio.file.Path;

final class DocumentNames {
    private DocumentNames() {}

    static Path basename(String input) {
        return Path.of(input).getFileName();
    }
}
