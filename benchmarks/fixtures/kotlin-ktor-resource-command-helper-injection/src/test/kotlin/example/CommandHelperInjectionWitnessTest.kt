package example

import kotlin.test.Test
import kotlin.test.assertEquals

class CommandHelperInjectionWitnessTest {
    @Test
    fun `command helper installs harmless shell grammar`() {
        val commandLine = "printf fixed; printf helper-expanded"
        val builder = ProcessBuilder("printf", "%s", "ignored")
        builder.command("sh", "-c", commandLine)
        val process = builder.start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("fixedhelper-expanded", stdout)
    }
}
