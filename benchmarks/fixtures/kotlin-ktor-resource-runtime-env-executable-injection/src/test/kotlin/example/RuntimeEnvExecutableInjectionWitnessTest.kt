package example

import kotlin.test.Test
import kotlin.test.assertEquals

class RuntimeEnvExecutableInjectionWitnessTest {
    @Test
    fun `Runtime exec array delegates the request position as a harmless executable`() {
        val requestProgram = "printf"
        val process = Runtime.getRuntime().exec(arrayOf("env", "--", requestProgram, "delegated-marker"))
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("delegated-marker", stdout)
    }
}
