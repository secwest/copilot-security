package example

import kotlin.test.Test
import kotlin.test.assertTrue

class ShellCommandWitnessTest {
    @Test
    fun `shell command position expands a harmless environment marker`() {
        val marker = "ktor-shell-expanded"
        val payload = "diagnostic; printf \$KOTLIN_COMMAND_MARKER"
        val process = ProcessBuilder("sh", "-c", payload)
            .apply { environment()["KOTLIN_COMMAND_MARKER"] = marker }
            .start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        assertTrue(stdout.contains(marker))
    }
}
