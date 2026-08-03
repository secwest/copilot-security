import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class SafePathWitness {
    private static String read(Path configuredRoot, String requested) throws Exception {
        Path root = configuredRoot.toRealPath();
        Path relative = Path.of(requested);
        if (relative.isAbsolute()) {
            throw new SecurityException("absolute");
        }
        Path candidate = root.resolve(relative).normalize();
        if (!candidate.startsWith(root)) {
            throw new SecurityException("lexical escape");
        }
        Path realCandidate = candidate.toRealPath();
        if (!realCandidate.startsWith(root)) {
            throw new SecurityException("link escape");
        }
        return Files.readString(realCandidate);
    }

    private static void expectRejected(Path root, String requested) throws Exception {
        try {
            read(root, requested);
            throw new AssertionError("Unsafe path was accepted: " + requested);
        } catch (SecurityException expected) {
            // Expected rejection.
        }
    }

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("copilot-security-java-safe-path-");
        try {
            Path documents = Files.createDirectories(workspace.resolve("documents"));
            Path guide = documents.resolve("guide.txt");
            Path privateFile = workspace.resolve("private.txt");
            Path sibling = Files.createDirectories(workspace.resolve("documents-backup"));
            Files.writeString(guide, "guide");
            Files.writeString(privateFile, "private");
            Files.writeString(sibling.resolve("backup.txt"), "backup");

            if (!read(documents, "guide.txt").equals("guide")) {
                throw new AssertionError("Valid in-root document was rejected");
            }
            expectRejected(documents, "../private.txt");
            expectRejected(documents, privateFile.toString());
            expectRejected(documents, "../documents-backup/backup.txt");

            Path link = documents.resolve("private-link.txt");
            try {
                Files.createSymbolicLink(link, privateFile);
                expectRejected(documents, "private-link.txt");
                System.out.println("Safe Java path witness rejected parent, absolute, sibling-prefix, and symlink escapes.");
            } catch (IOException | UnsupportedOperationException | SecurityException unavailable) {
                System.out.println("Safe Java path witness rejected parent, absolute, and sibling-prefix escapes; symbolic-link creation is unavailable on this host.");
            }
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
