package example

import kotlin.test.Test
import kotlin.test.assertEquals

class RuntimeListEnvArgvWitnessTest {
    @Test
    fun `Runtime exec converted list keeps the request value after a fixed executable`() {
        val requestValue = "delegated-marker"
        val command = listOf("env", "--", "printf", "%s", requestValue).toTypedArray()
        val process = Runtime.getRuntime().exec(command)
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("delegated-marker", stdout)
    }
}
