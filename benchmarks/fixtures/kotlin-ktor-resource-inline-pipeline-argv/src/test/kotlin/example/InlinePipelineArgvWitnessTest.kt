package example

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class InlinePipelineArgvWitnessTest {
    @Test
    fun `inline pipeline keeps shell-looking text in ordinary argv`() {
        val argument = "printf fixed; printf pipeline-expanded"
        val processes = ProcessBuilder.startPipeline(
            listOf(
                ProcessBuilder("printf", "%s", "ignored"),
                ProcessBuilder("printf", "%s", argument),
            ),
        )
        val stdout = processes.last().inputStream.bufferedReader().use { it.readText() }
        processes.forEach { it.waitFor() }
        assertEquals(argument, stdout)
        assertNotEquals("fixedpipeline-expanded", stdout)
    }
}
