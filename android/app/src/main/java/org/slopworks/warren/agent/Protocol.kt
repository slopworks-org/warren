package org.slopworks.warren.agent

import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal class Enrollment(val server: URI, val token: ByteArray) {
    companion object {
        fun parse(text: String): Enrollment {
            val uri = URI(text.trim().also { require(it.length <= 4096) })
            require(uri.scheme == "warren" && uri.rawAuthority == "enroll")
            require(uri.rawPath.isNullOrEmpty() && uri.rawFragment == null)
            val fields = requireNotNull(uri.rawQuery).split('&').map { item ->
                val parts = item.split('=', limit = 2)
                require(parts.size == 2)
                parts[0] to URLDecoder.decode(parts[1], Charsets.UTF_8.name())
            }
            val values = fields.toMap()
            require(fields.size == 3 && values.keys == setOf("v", "server", "token") && values["v"] == "1")
            val server = URI(values.getValue("server"))
            require(server.scheme == "https" && server.host != null && server.userInfo == null)
            require(server.rawPath in setOf("", "/") && server.query == null && server.fragment == null)
            require(server.port == -1 || server.port in 1..65535)
            val token = values.getValue("token")
            require(Regex("wrt_[A-Za-z0-9_-]{32}").matches(token))
            return Enrollment(server, Base64.getUrlDecoder().decode(token.substring(4)))
        }
    }
}

internal class Pairs private constructor(private val fields: List<Pair<String, String>>) {
    fun all(key: String) = fields.filter { it.first == key }.map { it.second }
    fun one(key: String) = all(key).single()
    fun encode(skip: String? = null) = fields.filterNot { it.first == skip }
        .joinToString(separator = "") { (key, value) -> "$key=$value\n" }

    companion object {
        fun of(vararg fields: Pair<String, String>) = Pairs(fields.map { (k, v) ->
            k to v.replace('\r', ' ').replace('\n', ' ').trim()
        })

        fun parse(text: String) = Pairs(text.lineSequence().map { it.trimEnd('\r') }
            .filterNot { it.isEmpty() || it.startsWith('#') }.map { line ->
                val parts = line.split('=', limit = 2)
                val key = parts[0].trim()
                require(parts.size == 2 && Regex("[A-Za-z0-9_]+").matches(key))
                key to parts[1].trim()
            }.toList())
    }
}

internal object Registration {
    private val random = SecureRandom()

    fun request(token: ByteArray, publicKey: ByteArray, name: String, os: String, version: String): SignedRequest {
        val nonce = ByteArray(16).also(random::nextBytes).hex()
        val fields = Pairs.of(
            "token_id" to token.copyOfRange(0, 6).hex(),
            "pubkey" to Base64.getEncoder().encodeToString(publicKey),
            "name" to name,
            "hostname" to name,
            "os" to os,
            "version" to version,
            "nonce" to nonce,
            "resume" to "1",
        ).encode()
        val signature = mac(token, "warren-register-resumable-request-v1\n$fields").hex()
        return SignedRequest(nonce, "${fields}mac=$signature\n")
    }

    fun verify(token: ByteArray, nonce: String, reply: Pairs): Boolean {
        val signature = reply.all("mac").singleOrNull() ?: return false
        if (!Regex("[0-9a-fA-F]{64}").matches(signature)) return false
        val expected = mac(token, "warren-register-reply-v1\n$nonce\n${reply.encode("mac")}")
        return MessageDigest.isEqual(expected, signature.unhex())
    }

    private fun mac(token: ByteArray, text: String): ByteArray {
        val secret = token.copyOfRange(6, 24)
        return try {
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
                .doFinal(text.toByteArray(Charsets.UTF_8))
        } finally {
            secret.fill(0)
        }
    }
}

internal class SignedRequest(val nonce: String, val body: String)

internal fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
internal fun String.unhex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
