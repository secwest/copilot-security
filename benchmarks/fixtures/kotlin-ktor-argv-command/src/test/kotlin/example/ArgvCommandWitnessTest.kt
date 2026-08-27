package example

import kotlin.test.Test
import kotlin.test.assertFalse

class ArgvCommandWitnessTest {
    @Test
    fun `ordinary process argument does not expand an environment marker`() {
        val marker = "ktor-argv-not-expanded"
        val payload = "\$KOTLIN_COMMAND_MARKER"
        val process = ProcessBuilder("printf", "%s", payload)
            .apply { environment()["KOTLIN_COMMAND_MARKER"] = marker }
            .start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        assertFalse(stdout.contains(marker))
    }
}
