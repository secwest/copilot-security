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
            val userValue = input.target
            val commandLine = userValue
            val builder = ProcessBuilder("printf", "%s", "fixed")
            builder.command("printf", "%s", commandLine)
            val process = builder.start()
            val stdout = process.inputStream.bufferedReader().use { it.readText() }
            call.respondText(stdout)
        }
    }
}
