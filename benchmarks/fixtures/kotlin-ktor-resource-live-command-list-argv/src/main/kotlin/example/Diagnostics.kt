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
            val command = arrayListOf("sh", "-c", input.target)
            val builder = ProcessBuilder(command)
            val liveCommand = builder.command()
            liveCommand.clear()
            liveCommand.add("printf")
            liveCommand.add("%s")
            liveCommand.add(input.target)
            val processBuilder = builder
            val process = processBuilder.start()
            val stdout = process.inputStream.bufferedReader().use { it.readText() }
            call.respondText(stdout)
        }
    }
}
