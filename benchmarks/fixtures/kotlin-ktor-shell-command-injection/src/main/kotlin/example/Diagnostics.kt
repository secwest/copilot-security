package example

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.lang.ProcessBuilder

fun Application.diagnosticsModule() {
    routing {
        get("/diagnostics") {
            val target = call.request.queryParameters["target"] ?: "localhost"
            val commandLine = "printf diagnostic; $target"
            val process = ProcessBuilder("sh", "-c", commandLine).start()
            val stdout = process.inputStream.bufferedReader().use { it.readText() }
            call.respondText(stdout)
        }
    }
}
