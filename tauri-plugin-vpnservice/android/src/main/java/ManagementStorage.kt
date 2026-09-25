package com.plugin.vpnservice

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Credential-encrypted, non-backed-up storage shared by the UI and future service host.
 * No Activity or WebView is required. Never replace an unreadable snapshot with defaults.
 */
@androidx.annotation.RequiresApi(23)
internal object ManagementStorage {
    private const val KEY_ALIAS = "easytier.management.v1"
    private val HEADER = byteArrayOf(0x45, 0x54, 0x4d, 0x01)

    private fun file(context: Context) = AtomicFile(
        File(context.applicationContext.noBackupFilesDir, "management-v1.enc")
    )

    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        check(create) { "Management storage key is unavailable" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build())
            generateKey()
        }
    }

    @Synchronized
    fun read(context: Context): String? {
        val target = file(context)
        val bytes = try { target.readFully() } catch (error: FileNotFoundException) {
            // AtomicFile can recover the legacy .bak format. Access errors are not absence.
            if (target.baseFile.exists() || File(target.baseFile.path + ".bak").exists()) throw error
            return null
        }
        require(bytes.size >= HEADER.size + 12 + 16 && bytes.copyOfRange(0, 4).contentEquals(HEADER)) {
            "Unsupported or damaged management storage"
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, bytes.copyOfRange(4, 16)))
        cipher.updateAAD(HEADER)
        return String(cipher.doFinal(bytes.copyOfRange(16, bytes.size)), Charsets.UTF_8)
    }

    @Synchronized
    fun write(context: Context, snapshot: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(true))
        require(cipher.iv.size == 12)
        cipher.updateAAD(HEADER)
        val bytes = HEADER + cipher.iv + cipher.doFinal(snapshot.toByteArray(Charsets.UTF_8))
        val target = file(context)
        val stream = target.startWrite()
        try {
            stream.write(bytes)
            target.finishWrite(stream)
            check(read(context) == snapshot) { "Management storage commit could not be verified" }
        } catch (error: Exception) {
            target.failWrite(stream)
            throw error
        }
    }
}
