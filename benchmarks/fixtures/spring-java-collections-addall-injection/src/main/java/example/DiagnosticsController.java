package example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public final class DiagnosticsController {
    @GetMapping("/diagnostics")
    public String diagnostics(@RequestParam("target") String target)
            throws IOException, InterruptedException {
        List<String> command = new LinkedList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        Collections.addAll(command, "sh", "-c", target);
        Process process = builder.start();
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("diagnostic process timed out");
        }
        if (process.exitValue() != 0) {
            throw new IOException("diagnostic process failed: " + process.exitValue());
        }
        return stdout;
    }
}
