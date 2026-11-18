package org.slopworks.warren.agent

import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.delay
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine
import org.slopworks.warren.BuildConfig
import org.slopworks.warren.vpn.WireGuard
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal enum class AgentFailure { TOKEN, NETWORK, PROTOCOL, SERVER_UPGRADE, REVOKED }
internal class AgentException(val failure: AgentFailure) : IOException()

internal data class Reply(val status: Int, val body: String, val routePageHeader: String? = null) {
    fun config(): AgentConfig {
        val fields = routePageHeader?.split(' ')?.let { parts ->
            require(parts.size == 3 && parts[0].toULongOrNull() != null && parts[2] in setOf("start", "end"))
            "version=${parts[0]}\nroute_peers=2\nroute_revision=${parts[1]}\nroute_next=${parts[2]}\n"
        }.orEmpty()
        return AgentConfig.parse(Pairs.parse(body + fields))
    }
}
internal const val MAX_RESPONSE = 256 * 1024

internal object AgentClient {
    private val name = Build.MODEL.orEmpty().filterNot(Char::isISOControl).take(64).ifBlank { "Android device" }
    private val os = "android-${Build.SUPPORTED_ABIS?.firstOrNull() ?: "unknown"}"

    fun prepareEnrollment(data: Enrollment): PendingEnrollment {
        val pair = WireGuard.keyPair() ?: throw AgentException(AgentFailure.PROTOCOL)
        val request = Registration.request(data.token, pair.substring(64).unhex(), name, os, BuildConfig.VERSION_NAME)
        return PendingEnrollment(data.server.toASCIIString(), pair.substring(0, 64), data.token, request)
    }

    suspend fun enroll(pending: PendingEnrollment): Profile = runInterruptible(Dispatchers.IO) {
        try {
            val request = pending.request
            // Warren's public registration listener uses HTTP port 80. The
            // token secret is only a MAC key, and the reply must prove it.
            val url = URL("http", URI(pending.server).host, 80, "/agent/v1/register-resumable")
            val conn = url.openConnection(Proxy.NO_PROXY) as HttpURLConnection
            val reply = try {
                conn.instanceFollowRedirects = false
                conn.connectTimeout = 8000
                conn.readTimeout = 10000
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "text/plain; charset=utf-8")
                val body = request.body.toByteArray(Charsets.UTF_8)
                conn.setFixedLengthStreamingMode(body.size)
                conn.outputStream.use { it.write(body) }
                val status = conn.responseCode
                Reply(status, if (status == 200) conn.inputStream.use { it.readBounded() } else "")
            } finally {
                conn.disconnect()
            }
            if (reply.status in setOf(404, 308)) throw AgentException(AgentFailure.SERVER_UPGRADE)
            if (reply.status in setOf(403, 409, 410)) throw AgentException(AgentFailure.TOKEN)
            if (reply.status != 200) throw AgentException(AgentFailure.PROTOCOL)
            val fields = Pairs.parse(reply.body)
            if (!Registration.verify(pending.token, request.nonce, fields) || fields.one("resume") != "1") {
                throw AgentException(AgentFailure.PROTOCOL)
            }
            Profile(pending.server, pending.privateKey, AgentConfig.parse(fields))
        } catch (e: AgentException) {
            throw e
        } catch (_: IOException) {
            throw AgentException(AgentFailure.NETWORK)
        } catch (_: IllegalArgumentException) {
            throw AgentException(AgentFailure.PROTOCOL)
        } catch (_: NoSuchElementException) {
            throw AgentException(AgentFailure.PROTOCOL)
        }
    }

    suspend fun poll(
        config: AgentConfig, wait: Int, lan: List<Prefix>, port: Int, onForbidden: () -> Unit,
    ): AgentConfig? {
        val lanReport = if (lan.isNotEmpty() && port > 0) {
            "&mesh=2&port=$port&lan=${encode(lan.joinToString(","))}"
        } else ""
        val path = "/agent/v1/config?v=${config.version}&wait=$wait&agent=${BuildConfig.VERSION_NAME}" +
            "&hostname=${encode(name)}&os=${encode(os)}&route_peers=1&route_pages=true$lanReport"
        val reply = exchange(config, path, wait)
        return when (reply.status) {
            200 -> reply.config().also { check(it.deviceId == config.deviceId) }
            204, 304 -> null
            403 -> {
                onForbidden()
                throw AgentException(AgentFailure.REVOKED)
            }
            else -> throw AgentException(AgentFailure.PROTOCOL)
        }
    }

    suspend fun routePeers(config: AgentConfig): List<RoutePeer>? = try {
        config.collectRoutePeers { path -> routePage(config, path) }
    } catch (_: IllegalArgumentException) {
        throw AgentException(AgentFailure.PROTOCOL)
    } catch (_: NoSuchElementException) {
        throw AgentException(AgentFailure.PROTOCOL)
    }

    private suspend fun routePage(config: AgentConfig, path: String): Reply {
        var backoff = 1000L
        while (true) {
            try {
                return exchange(config, path, wait = 0)
            } catch (_: IOException) {
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(5000L)
            }
        }
    }

    private suspend fun exchange(config: AgentConfig, path: String, wait: Int): Reply =
        suspendCancellableCoroutine { continuation ->
            val socket = Socket(Proxy.NO_PROXY)
            continuation.invokeOnCancellation { runCatching { socket.close() } }
            Dispatchers.IO.asExecutor().execute {
                try {
                    val response = socket.use {
                        it.soTimeout = (wait + 5) * 1000
                        it.bind(InetSocketAddress(config.address.ip.inet(), 0))
                        it.connect(InetSocketAddress(Ipv4.parse(config.control.host).inet(), config.control.port), 5000)
                        it.getOutputStream().write(
                            "GET $path HTTP/1.0\r\nHost: ${config.control}\r\n\r\n".toByteArray(Charsets.US_ASCII),
                        )
                        val input = BufferedInputStream(it.getInputStream())
                        val status = input.line().split(' ').getOrNull(1)?.toIntOrNull() ?: throw IOException()
                        var header = input.line()
                        var count = 0
                        var length: Int? = null
                        var routePageHeader: String? = null
                        while (header.isNotEmpty()) {
                            if (++count > 64 || header.startsWith("transfer-encoding:", ignoreCase = true)) throw IOException()
                            if (header.startsWith("content-length:", ignoreCase = true)) {
                                length = header.substringAfter(':').trim().toIntOrNull() ?: throw IOException()
                            }
                            if (header.startsWith("warren-route-page:", ignoreCase = true)) {
                                if (routePageHeader != null) throw IOException()
                                routePageHeader = header.substringAfter(':').trim()
                            }
                            header = input.line()
                        }
                        Reply(status, if (status == 200) input.readBounded(length) else "", routePageHeader)
                    }
                    continuation.resume(response)
                } catch (e: Exception) {
                    continuation.resumeWithException(e)
                }
            }
        }

    private fun encode(text: String) = URLEncoder.encode(text, Charsets.UTF_8.name())

    private fun InputStream.line(): String = buildString {
        repeat(8192) {
            when (val next = read()) {
                -1 -> throw IOException()
                10 -> return@buildString
                13 -> Unit
                else -> append(next.toChar())
            }
        }
        throw IOException()
    }

    private fun InputStream.readBounded(length: Int? = null): String {
        if (length != null && length !in 0..MAX_RESPONSE) throw IOException()
        val max = length ?: MAX_RESPONSE + 1
        val bytes = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (bytes.size() < max) {
            val count = read(buffer, 0, minOf(buffer.size, max - bytes.size()))
            if (count == -1) break
            bytes.write(buffer, 0, count)
        }
        if (bytes.size() > MAX_RESPONSE || (length != null && bytes.size() != length)) throw IOException()
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }
}
