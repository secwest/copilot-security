package example

import kotlin.test.Test
import kotlin.test.assertEquals

class EnvArgvWitnessTest {
    @Test
    fun `env keeps the request value after a fixed executable`() {
        val requestValue = "delegated-marker"
        val process = ProcessBuilder("env", "--", "printf", "%s", requestValue).start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("delegated-marker", stdout)
    }
}
