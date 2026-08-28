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
            val process = Runtime.getRuntime().exec(arrayOf("env", "--", input.target))
            val stdout = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor()
            call.respondText(stdout)
        }
    }
}
