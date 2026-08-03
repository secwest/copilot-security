import java.nio.file.Files;
import java.nio.file.Path;

public final class VulnerablePathWitness {
    private static String read(Path root, String requested) throws Exception {
        return Files.readString(root.resolve(requested));
    }

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("copilot-security-java-path-");
        try {
            Path documents = Files.createDirectories(workspace.resolve("documents"));
            Path privateFile = workspace.resolve("private.txt");
            Files.writeString(privateFile, "private-value");

            if (!read(documents, "../private.txt").equals("private-value")) {
                throw new AssertionError("Parent traversal did not escape the document root");
            }
            if (!read(documents, privateFile.toString()).equals("private-value")) {
                throw new AssertionError("Absolute path did not replace the document root");
            }
            System.out.println("Vulnerable Java path witness escaped by parent traversal and absolute-path reset.");
        } finally {
            try (var paths = Files.walk(workspace)) {
                paths.sorted((left, right) -> right.compareTo(left)).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Exception ignored) {
                        // Best-effort cleanup after the assertions have completed.
                    }
                });
            }
        }
    }
}
