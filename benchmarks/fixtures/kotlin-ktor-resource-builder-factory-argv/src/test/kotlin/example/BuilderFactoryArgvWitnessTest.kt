package example

import kotlin.test.Test
import kotlin.test.assertEquals

class BuilderFactoryArgvWitnessTest {
    @Test
    fun `builder factory keeps shell-looking text as one argv value`() {
        val commandLine = "printf fixed; printf factory-expanded"
        val process = ProcessBuilder("printf", "%s", commandLine).start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals(commandLine, stdout)
    }
}
