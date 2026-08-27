package example

import kotlin.test.Test
import kotlin.test.assertFalse

class ResourceArgvCommandWitnessTest {
    @Test
    fun `replacement ordinary argument does not expand an environment marker`() {
        val marker = "ktor-resource-argv-not-expanded"
        val payload = "\$KOTLIN_RESOURCE_COMMAND_MARKER"
        val builder = ProcessBuilder("sh", "-c", "printf unsafe")
        builder.command("printf", "%s", payload)
        builder.environment()["KOTLIN_RESOURCE_COMMAND_MARKER"] = marker
        val process = builder.start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        assertFalse(stdout.contains(marker))
    }
}
