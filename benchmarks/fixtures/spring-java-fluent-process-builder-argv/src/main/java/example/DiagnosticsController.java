package example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public final class DiagnosticsController {
    @GetMapping("/diagnostics")
    public String diagnostics(@RequestParam("target") String target)
            throws IOException, InterruptedException {
        Process process = new ProcessBuilder()
                .redirectErrorStream(true)
                .command("printf", "%s", target)
                .start();
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int status = process.waitFor();
        if (status != 0) {
            throw new IOException("diagnostic process failed: " + status);
        }
        return stdout;
    }
}
