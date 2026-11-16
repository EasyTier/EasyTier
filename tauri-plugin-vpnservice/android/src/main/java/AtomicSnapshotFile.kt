package com.plugin.vpnservice

import androidx.core.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream

/** All access must be serialized by the owner, including reads during recovery. */
internal class AtomicSnapshotFile(
    private val base: File,
    private val sync: (FileOutputStream) -> Unit = { it.fd.sync() },
    private val verify: (ByteArray, ByteArray) -> Boolean = { actual, expected -> actual.contentEquals(expected) },
) {
    private val atomic = AtomicFile(base)

    fun read(): ByteArray? = try {
        atomic.readFully()
    } catch (error: FileNotFoundException) {
        // Only true absence permits migration. Never interpret permissions/I/O errors as absence.
        val entries = base.parentFile?.list() ?: throw error
        if (entries.contains(base.name) || entries.contains(base.name + ".bak")) throw error
        null // An abandoned .new from the first write is not a committed snapshot.
    }

    fun write(bytes: ByteArray) {
        val stream = atomic.startWrite()
        try {
            stream.write(bytes)
            // AtomicFile logs sync errors internally; surface them before entering commit.
            sync(stream)
        } catch (error: Exception) {
            atomic.failWrite(stream)
            throw error
        }

        // No rollback beyond this boundary. finishWrite may have replaced the base file
        // even if verification subsequently fails. The Rust repository must re-read it.
        atomic.finishWrite(stream)
        check(verify(atomic.readFully(), bytes)) { "Management storage commit is uncertain" }
    }
}
