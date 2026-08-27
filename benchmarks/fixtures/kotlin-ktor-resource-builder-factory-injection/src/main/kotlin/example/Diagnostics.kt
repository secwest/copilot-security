package example

import io.ktor.resources.Resource
import io.ktor.server.application.*
import io.ktor.server.resources.*
import io.ktor.server.response.*
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

private fun diagnosticProcess(commandLine: String): ProcessBuilder =
    ProcessBuilder("sh", "-c", commandLine)

fun Application.diagnosticsModule() {
    install(Resources)
    routing {
        get<DiagnosticResource> { input ->
            val commandLine = "printf diagnostic; ${input.target}"
            val process = diagnosticProcess(commandLine).start()
            val stdout = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor()
            call.respondText(stdout)
        }
    }
}
