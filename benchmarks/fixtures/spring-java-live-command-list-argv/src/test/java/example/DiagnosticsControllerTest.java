package example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class DiagnosticsControllerTest {
    @Test
    void preservesMetacharactersAsOrdinaryArgumentData() throws Exception {
        String value = "literal;$(not-executed)&data";
        assertEquals(value, new DiagnosticsController().diagnostics(value));
    }
}
