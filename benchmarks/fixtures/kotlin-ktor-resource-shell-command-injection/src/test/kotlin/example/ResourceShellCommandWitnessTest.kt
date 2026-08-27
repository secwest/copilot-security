package example

import kotlin.test.Test
import kotlin.test.assertTrue

class ResourceShellCommandWitnessTest {
    @Test
    fun `replacement shell command expands a harmless environment marker`() {
        val marker = "ktor-resource-shell-expanded"
        val payload = "diagnostic; printf \$KOTLIN_RESOURCE_COMMAND_MARKER"
        val builder = ProcessBuilder("printf", "%s", "fixed")
        builder.command("sh", "-c", payload)
        builder.environment()["KOTLIN_RESOURCE_COMMAND_MARKER"] = marker
        val process = builder.start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        assertTrue(stdout.contains(marker))
    }
}
