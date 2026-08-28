package example

import kotlin.test.Test
import kotlin.test.assertEquals

class RuntimeEnvArgvWitnessTest {
    @Test
    fun `Runtime exec array keeps the request value after a fixed executable`() {
        val requestValue = "delegated-marker"
        val process = Runtime.getRuntime().exec(arrayOf("env", "--", "printf", "%s", requestValue))
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("delegated-marker", stdout)
    }
}
