package example;

import java.io.File;

final class DocumentNames {
    private DocumentNames() {}

    static String basename(String input) {
        return new File(input).getName();
    }
}
