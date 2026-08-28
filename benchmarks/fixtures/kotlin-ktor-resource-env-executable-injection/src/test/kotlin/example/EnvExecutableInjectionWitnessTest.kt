package example

import kotlin.test.Test
import kotlin.test.assertEquals

class EnvExecutableInjectionWitnessTest {
    @Test
    fun `env treats the request position as a harmless executable name`() {
        val requestProgram = "printf"
        val process = ProcessBuilder("env", "--", requestProgram, "delegated-marker").start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("delegated-marker", stdout)
    }
}
