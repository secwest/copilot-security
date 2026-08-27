package example

import kotlin.test.Test
import kotlin.test.assertFalse

class LiveCommandListArgvWitnessTest {
    @Test
    fun `rebuilt ordinary argv does not expand an environment marker`() {
        val marker = "ktor-live-command-list-not-expanded"
        val payload = "\$KOTLIN_LIVE_COMMAND_MARKER"
        val command = arrayListOf("sh", "-c", payload)
        val builder = ProcessBuilder(command)
        val liveCommand = builder.command()
        liveCommand.clear()
        liveCommand.add("printf")
        liveCommand.add("%s")
        liveCommand.add(payload)
        val processBuilder = builder
        processBuilder.environment()["KOTLIN_LIVE_COMMAND_MARKER"] = marker
        val process = processBuilder.start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        assertFalse(stdout.contains(marker))
    }
}
