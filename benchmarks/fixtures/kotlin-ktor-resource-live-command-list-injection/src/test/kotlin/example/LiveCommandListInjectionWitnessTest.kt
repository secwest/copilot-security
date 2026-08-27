package example

import kotlin.test.Test
import kotlin.test.assertTrue

class LiveCommandListInjectionWitnessTest {
    @Test
    fun `live command list installs a harmless marker-expanding shell command`() {
        val marker = "ktor-live-command-list-expanded"
        val payload = "diagnostic; printf \$KOTLIN_LIVE_COMMAND_MARKER"
        val command = arrayListOf("sh", "-c", "printf fixed")
        val builder = ProcessBuilder(command)
        val liveCommand = builder.command()
        liveCommand.set(2, payload)
        val processBuilder = builder
        processBuilder.environment()["KOTLIN_LIVE_COMMAND_MARKER"] = marker
        val process = processBuilder.start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        assertTrue(stdout.contains(marker))
    }
}
