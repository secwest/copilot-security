package example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class DiagnosticsControllerTest {
    @Test
    void keepsShellMetacharactersInOneArgument() throws Exception {
        String target = "spring-java-copy;printf expanded";
        assertEquals(target, new DiagnosticsController().diagnostics(target));
    }
}
