import java.nio.file.Files;
import java.nio.file.Path;

public final class SafePathGetFileNameWitness {
    private static String read(Path root, String requested) throws Exception {
        Path basename = Path.of(requested).getFileName();
        if (Path.of("..").equals(basename)) {
            throw new SecurityException("parent path components are forbidden");
        }
        return Files.readString(root.resolve(basename).resolve("content.txt"));
    }

    private static void expectRejected(Path root, String requested) throws Exception {
        try {
            read(root, requested);
            throw new AssertionError("Expected rejection for " + requested);
        } catch (SecurityException expected) {
            // Exact fail-closed control.
        }
    }

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("copilot-security-java-path-file-name-safe-");
        try {
            Path documents = Files.createDirectories(workspace.resolve("documents"));
            Path guide = Files.createDirectories(documents.resolve("guide"));
            Files.writeString(guide.resolve("content.txt"), "public-guide");
            Files.writeString(workspace.resolve("content.txt"), "workspace-secret");

            expectRejected(documents, "..");
            expectRejected(documents, "nested/..");
            if (!read(documents, "guide").equals("public-guide")) {
                throw new AssertionError("The ordinary basename control did not remain usable");
            }
            System.out.println("Safe Path.getFileName witness rejected parent basenames before the sink.");
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
