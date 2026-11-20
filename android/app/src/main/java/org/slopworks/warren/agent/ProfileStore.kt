package org.slopworks.warren.agent

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class Profile(val server: String, val privateKey: String, val config: AgentConfig) {
    fun withConfig(config: AgentConfig) = Profile(server, privateKey, config)
}

internal class PendingEnrollment(
    val server: String,
    val privateKey: String,
    val token: ByteArray,
    val request: SignedRequest,
)

internal class ProfileStore(
    private val readBytes: () -> ByteArray,
    private val writeBytes: (ByteArray) -> Unit,
    private val key: (create: Boolean) -> SecretKey,
    private val legacyWantsVpn: () -> Boolean,
) {
    constructor(context: Context) : this(
        AtomicFile(File(context.noBackupFilesDir, "agent")),
        { context.getSharedPreferences("connection", Context.MODE_PRIVATE).getBoolean("connected", false) },
    )

    private constructor(file: AtomicFile, legacyWantsVpn: () -> Boolean) :
        this(file::readFully, { file.writeVerified(it) }, ::androidKey, legacyWantsVpn)

    var wantsVpn: Boolean
        get() = synchronized(lock) {
            val json = read()
            json.wantsVpn()
        }
        set(value) = synchronized(lock) {
            val json = read()
            if (value) check(json.has("key") && !json.retiring())
            if (json.wantsVpn() != value) {
                write(json.put("connected", value))
            }
        }

    fun load(): Profile? = synchronized(lock) { read().profile() }

    fun activeProfile(): Profile? = synchronized(lock) {
        val json = read()
        if (json.wantsVpn()) json.profile() else null
    }

    fun enrollmentState(): Pair<Profile?, Boolean> = synchronized(lock) {
        val json = read()
        json.profile() to json.has("pending")
    }

    fun beginEnrollment(pending: PendingEnrollment) = synchronized(lock) {
        val json = read()
        check(!json.has("pending"))
        val transaction = JSONObject()
            .put("server", pending.server)
            .put("key", pending.privateKey)
            .put("token", Base64.getEncoder().encodeToString(pending.token))
            .put("nonce", pending.request.nonce)
            .put("request", pending.request.body)
        write(json.put("pending", transaction))
    }

    fun pendingEnrollment(): PendingEnrollment = synchronized(lock) {
        val transaction = read().getJSONObject("pending")
        PendingEnrollment(
            transaction.getString("server"),
            transaction.privateKey(),
            Base64.getDecoder().decode(transaction.getString("token")),
            SignedRequest(transaction.getString("nonce"), transaction.getString("request")),
        )
    }

    fun cancelEnrollment() = synchronized(lock) {
        val json = read()
        if (json.remove("pending") != null) write(json)
    }

    fun pauseForEnrollment(pending: PendingEnrollment) = synchronized(lock) {
        val json = read()
        val transaction = json.transaction(pending)
        if (json.has("key") && !json.retiring()) {
            // Keep the receipt and old profile after an interrupted replacement.
            // Neither a boot restore nor a tile tap may start it in this state.
            transaction.put("retiring", true)
            write(json.put("connected", false))
        }
    }

    fun completeEnrollment(pending: PendingEnrollment, profile: Profile) = synchronized(lock) {
        val json = read()
        json.transaction(pending)
        check(!json.has("key") || json.retiring())
        json.remove("pending")
        write(json.put("server", profile.server).put("key", profile.privateKey)
            .put("config", AgentConfig.bootstrapWire(profile.config.wire)).put("connected", false))
    }

    fun saveConfig(profile: Profile) = synchronized(lock) {
        val json = read()
        if (json.wantsVpn() && json.optString("key") == profile.privateKey) {
            val bootstrap = AgentConfig.bootstrapWire(profile.config.wire)
            if (json.getString("config") != bootstrap) write(json.put("config", bootstrap))
        }
    }

    private fun JSONObject.transaction(pending: PendingEnrollment): JSONObject =
        getJSONObject("pending").also { check(it.getString("request") == pending.request.body) }

    private fun JSONObject.retiring(): Boolean = optJSONObject("pending")?.optBoolean("retiring") == true

    private fun JSONObject.wantsVpn(): Boolean =
        has("key") && !retiring() && optBoolean("connected", legacyWantsVpn())

    private fun JSONObject.privateKey(): String =
        getString("key").also { require(Regex("[0-9a-f]{64}").matches(it)) }

    private fun JSONObject.profile(): Profile? =
        if (has("key")) Profile(getString("server"), privateKey(), AgentConfig.parse(Pairs.parse(getString("config"))))
        else null

    private fun read(): JSONObject {
        val bytes = try { readBytes() } catch (_: FileNotFoundException) { return JSONObject() }
        require(bytes.size in 29..(1024 * 1024))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        val plain = cipher.doFinal(bytes, 12, bytes.size - 12)
        val json = try {
            JSONObject(String(plain, Charsets.UTF_8))
        } finally {
            plain.fill(0)
        }
        // Rewrite legacy files before making them available to readers or writers.
        // The store lock covers migration, intent changes and all config saves.
        if (json.has("config")) {
            val wire = json.getString("config")
            val bootstrap = AgentConfig.bootstrapWire(wire)
            if (wire != bootstrap) write(json.put("config", bootstrap))
        }
        return json
    }

    private fun write(json: JSONObject) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(true))
        check(cipher.iv.size == 12)
        val plain = json.toString().toByteArray(Charsets.UTF_8)
        val bytes = try {
            cipher.iv + cipher.doFinal(plain)
        } finally {
            plain.fill(0)
        }
        writeBytes(bytes)
    }

    companion object {
        private const val KEY_ALIAS = "warren.agent.v1"
        private val lock = Any()

        private fun androidKey(create: Boolean): SecretKey {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
            check(create)
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build())
                generateKey()
            }
        }
    }
}

private fun AtomicFile.writeVerified(bytes: ByteArray) {
    val out = startWrite()
    try {
        out.write(bytes)
        out.fd.sync()
    } catch (e: Exception) {
        failWrite(out)
        throw e
    }
    finishWrite(out)
    // AtomicFile reports a failed rename in the log. Verify the committed
    // bytes before allowing a request to consume its token.
    check(readFully().contentEquals(bytes))
}
