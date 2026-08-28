package example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class DiagnosticsControllerTest {
    @Test
    void executesOnlyTheBoundedFixedStringWitness() throws Exception {
        String output = new DiagnosticsController().diagnostics("printf spring-java-caller-expanded");
        assertEquals("spring-java-caller-expanded", output);
    }
}
