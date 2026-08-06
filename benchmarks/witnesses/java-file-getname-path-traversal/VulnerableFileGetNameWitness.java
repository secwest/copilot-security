import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

public final class VulnerableFileGetNameWitness {
    private static String read(Path root, String requested) throws Exception {
        String basename = new File(requested).getName();
        return Files.readString(root.resolve(basename).resolve("content.txt"));
    }

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("copilot-security-java-file-name-");
        try {
            Path documents = Files.createDirectories(workspace.resolve("documents"));
            Path guide = Files.createDirectories(documents.resolve("guide"));
            Files.writeString(guide.resolve("content.txt"), "public-guide");
            Files.writeString(workspace.resolve("content.txt"), "workspace-secret");

            if (!read(documents, "..").equals("workspace-secret")) {
                throw new AssertionError("File.getName did not preserve the parent component");
            }
            if (!read(documents, "guide").equals("public-guide")) {
                throw new AssertionError("The ordinary basename control did not remain usable");
            }
            System.out.println("Vulnerable File.getName witness escaped the document root with '..'.");
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
