package example

import io.ktor.resources.Resource
import io.ktor.server.application.*
import io.ktor.server.resources.*
import io.ktor.server.response.*
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun Application.diagnosticsModule() {
    install(Resources)
    routing {
        get<DiagnosticResource> { input ->
            val commandLine = "printf diagnostic; ${input.target}"
            val processes = ProcessBuilder.startPipeline(
                listOf(
                    ProcessBuilder("printf", "%s", "fixed"),
                    ProcessBuilder("sh", "-c", commandLine),
                ),
            )
            val stdout = processes.last().inputStream.bufferedReader().use { it.readText() }
            call.respondText(stdout)
        }
    }
}
