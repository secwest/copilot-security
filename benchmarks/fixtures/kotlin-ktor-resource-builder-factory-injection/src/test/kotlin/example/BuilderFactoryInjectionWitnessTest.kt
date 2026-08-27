package example

import kotlin.test.Test
import kotlin.test.assertEquals

class BuilderFactoryInjectionWitnessTest {
    @Test
    fun `builder factory preserves harmless shell grammar`() {
        val commandLine = "printf fixed; printf factory-expanded"
        val process = ProcessBuilder("sh", "-c", commandLine).start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        assertEquals("fixedfactory-expanded", stdout)
    }
}
