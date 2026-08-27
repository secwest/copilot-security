package example

import kotlin.test.Test
import kotlin.test.assertEquals

class CommandHelperArgvWitnessTest {
    @Test
    fun `command helper keeps shell-looking text as one argv value`() {
        val commandLine = "printf fixed; printf helper-expanded"
        val builder = ProcessBuilder("printf", "%s", "ignored")
        builder.command("printf", "%s", commandLine)
        val process = builder.start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals(commandLine, stdout)
    }
}
