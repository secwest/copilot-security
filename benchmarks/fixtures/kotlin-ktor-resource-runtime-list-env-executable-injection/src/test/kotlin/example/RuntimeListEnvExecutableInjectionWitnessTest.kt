package example

import kotlin.test.Test
import kotlin.test.assertEquals

class RuntimeListEnvExecutableInjectionWitnessTest {
    @Test
    fun `Runtime exec converted list delegates the request position as a harmless executable`() {
        val requestProgram = "printf"
        val command = listOf("env", "--", requestProgram, "delegated-marker").toTypedArray()
        val process = Runtime.getRuntime().exec(command)
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("delegated-marker", stdout)
    }
}
