package com.mobsec.companion

import com.mobsec.companion.protocol.CommandRequest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import java.io.BufferedReader
import java.io.Closeable
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.io.PrintWriter
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Minimal HTTP server that works in Android's app_process runtime.
 * Avoids Ktor/Netty which require JVM features not available on-device.
 */
private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
private val router = CommandRouter.default()
private const val COMPANION_SERVICE_NAME = "maya-companion-android"
private const val MAX_BODY_BYTES = 1_048_576L
private const val MAX_HEADERS = 100

private class ResponseGate {
    var sent: Boolean = false
}

object CompanionHttpServer : Closeable {
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var executor: ExecutorService? = null

    fun isRunning(): Boolean = running.get()

    @Synchronized
    fun start(port: Int = defaultPort()): Result<Int> {
        if (running.get()) {
            return Result.success(server?.localPort ?: port)
        }

        return runCatching {
            val serverSocket = ServerSocket(port)
            val pool = Executors.newFixedThreadPool(4)
            server = serverSocket
            executor = pool
            running.set(true)

            acceptThread = Thread({
                while (running.get()) {
                    try {
                        val client = serverSocket.accept()
                        pool.submit { handleClient(client) }
                    } catch (e: Exception) {
                        if (running.get()) {
                            System.err.println("Accept error: ${e.message}")
                        }
                    }
                }
            }, "companion-http-accept")
            acceptThread?.isDaemon = true
            acceptThread?.start()

            println("MOBSEC Companion Server v2.0.0 listening on 0.0.0.0:$port")
            CompanionLog.add("Server started on port $port")
            port
        }
    }

    @Synchronized
    override fun close() {
        running.set(false)
        CompanionLog.add("Server stopped")
        try {
            server?.close()
        } catch (_: Exception) {
        }
        server = null
        acceptThread = null
        executor?.shutdownNow()
        executor = null
    }
}

fun defaultPort(): Int = System.getenv("COMPANION_PORT")?.toIntOrNull() ?: 9999

fun main() {
    val port = defaultPort()
    val result = CompanionHttpServer.start(port)
    if (result.isFailure) {
        val error = result.exceptionOrNull()
        System.err.println(
            "Failed to start companion server on port $port: ${error?.message ?: "unknown error"}",
        )
        return
    }

    while (true) {
        Thread.sleep(60_000)
    }
}

private fun handleClient(socket: Socket) {
    val gate = ResponseGate()
    try {
        socket.soTimeout = 30_000
        val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
        val writer = PrintWriter(OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), false)
        try {
            serve(reader, writer, gate)
        } catch (e: Exception) {
            System.err.println("Client error: ${e.message}")
            writeHttp(writer, gate, "500 Internal Server Error", errorJson("internal error"))
        }
    } catch (e: Exception) {
        System.err.println("Client error: ${e.message}")
    } finally {
        try {
            socket.close()
        } catch (_: Exception) {
        }
    }
}

private fun serve(reader: BufferedReader, writer: PrintWriter, gate: ResponseGate) {
    val requestLine = reader.readLine() ?: return
    val parts = requestLine.split(" ")
    if (parts.size < 2 || parts[0].isBlank()) {
        writeHttp(writer, gate, "400 Bad Request", errorJson("malformed request"))
        return
    }
    val method = parts[0]
    val path = parts[1].substringBefore("?")

    var headerCount = 0
    var contentLength: Long? = null
    var invalidContentLength = false
    while (true) {
        val line = reader.readLine() ?: break
        if (line.isEmpty()) break
        headerCount += 1
        if (headerCount > MAX_HEADERS) {
            writeHttp(writer, gate, "400 Bad Request", errorJson("too many headers"))
            return
        }
        val pieces = line.split(": ", limit = 2)
        val key = pieces[0].lowercase()
        val value = if (pieces.size == 2) pieces[1] else ""
        if (key == "content-length") {
            val parsed = value.trim().toLongOrNull()
            if (parsed == null || parsed < 0) {
                invalidContentLength = true
            } else {
                contentLength = parsed
            }
        }
    }

    if (invalidContentLength) {
        writeHttp(writer, gate, "400 Bad Request", errorJson("invalid content-length"))
        return
    }
    val length = contentLength ?: 0L
    if (length > MAX_BODY_BYTES) {
        writeHttp(writer, gate, "413 Payload Too Large", errorJson("body too large"))
        return
    }

    val body = if (length > 0) {
        val expected = length.toInt()
        val buf = CharArray(expected)
        var read = 0
        while (read < expected) {
            val n = reader.read(buf, read, expected - read)
            if (n == -1) break
            read += n
        }
        String(buf, 0, read)
    } else {
        ""
    }

    val (statusCode, responseBody) = route(method, path, body)
    CompanionLog.add("$method $path → $statusCode")
    writeHttp(writer, gate, statusCode, responseBody)
}

private fun writeHttp(writer: PrintWriter, gate: ResponseGate, statusLine: String, responseBody: String) {
    if (gate.sent) return
    gate.sent = true
    val bytes = responseBody.toByteArray(StandardCharsets.UTF_8)
    writer.print("HTTP/1.1 $statusLine\r\n")
    writer.print("Content-Type: application/json; charset=utf-8\r\n")
    writer.print("Content-Length: ${bytes.size}\r\n")
    writer.print("Connection: close\r\n")
    writer.print("\r\n")
    writer.print(responseBody)
    writer.flush()
}

private fun errorJson(message: String): String {
    return json.encodeToString(mapOf("status" to "error", "error" to message))
}

private fun route(method: String, path: String, body: String): Pair<String, String> {
    return try {
        when {
            path == "/health" && method == "GET" -> {
                val data = mapOf("status" to "ok", "service" to COMPANION_SERVICE_NAME, "version" to "2.0.0")
                "200 OK" to json.encodeToString(data)
            }
            path == "/health" -> "405 Method Not Allowed" to errorJson("method not allowed")
            path == "/commands" && method == "GET" -> {
                val data = mapOf("status" to "ok", "info" to "Use POST /command with {id, command, params}")
                "200 OK" to json.encodeToString(data)
            }
            path == "/commands" -> "405 Method Not Allowed" to errorJson("method not allowed")
            path == "/command" && method == "POST" -> dispatchCommand(body)
            path == "/command" -> "405 Method Not Allowed" to errorJson("method not allowed")
            else -> {
                val err = mapOf("status" to "error", "error" to "not found", "path" to path)
                "404 Not Found" to json.encodeToString(err)
            }
        }
    } catch (_: Exception) {
        "500 Internal Server Error" to errorJson("internal error")
    }
}

private fun dispatchCommand(body: String): Pair<String, String> {
    if (body.isBlank()) {
        return "400 Bad Request" to errorJson("empty body")
    }
    val request = try {
        json.decodeFromString<CommandRequest>(body)
    } catch (_: SerializationException) {
        return "400 Bad Request" to errorJson("invalid json")
    }
    if (request.id.isBlank()) {
        return "400 Bad Request" to errorJson("id is required")
    }
    if (request.command.isBlank()) {
        return "400 Bad Request" to errorJson("command is required")
    }
    val response = router.handle(request)
    val status = if (response.status == "success") "200 OK" else "400 Bad Request"
    return status to json.encodeToString(response)
}