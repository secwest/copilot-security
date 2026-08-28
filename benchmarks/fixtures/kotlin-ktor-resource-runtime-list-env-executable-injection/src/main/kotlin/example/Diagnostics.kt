package example

import io.ktor.resources.Resource
import io.ktor.server.application.*
import io.ktor.server.resources.*
import io.ktor.server.response.*
import io.ktor.server.routing.routing

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun Application.diagnosticsModule() {
    install(Resources)
    routing {
        get<DiagnosticResource> { input ->
            val command = listOf("env", "--", input.target).toTypedArray()
            val process = Runtime.getRuntime().exec(command)
            val stdout = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor()
            call.respondText(stdout)
        }
    }
}
