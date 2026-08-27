package example

import kotlin.test.Test
import kotlin.test.assertEquals

class InlinePipelineInjectionWitnessTest {
    @Test
    fun `inline pipeline interprets a harmless shell command sequence`() {
        val commandLine = "printf fixed; printf pipeline-expanded"
        val processes = ProcessBuilder.startPipeline(
            listOf(
                ProcessBuilder("printf", "%s", "ignored"),
                ProcessBuilder("sh", "-c", commandLine),
            ),
        )
        val stdout = processes.last().inputStream.bufferedReader().use { it.readText() }
        processes.forEach { it.waitFor() }
        assertEquals("fixedpipeline-expanded", stdout)
    }
}
