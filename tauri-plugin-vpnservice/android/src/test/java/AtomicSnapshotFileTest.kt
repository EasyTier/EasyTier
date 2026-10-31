package com.plugin.vpnservice

import java.io.File
import java.io.IOException
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class AtomicSnapshotFileTest {
    @get:Rule val directory = TemporaryFolder()
    private fun base() = File(directory.root, "snapshot.enc")

    @Test fun roundTripAndReplace() {
        val store = AtomicSnapshotFile(base())
        assertNull(store.read())
        store.write("old".toByteArray())
        store.write("new".toByteArray())
        assertEquals("new", String(store.read()!!))
    }

    @Test fun interruptedFirstWriteDoesNotBecomeCanonical() {
        File(base().path + ".new").writeText("partial ciphertext")
        val store = AtomicSnapshotFile(base())
        assertNull(store.read())
        store.write("retried migration".toByteArray())
        assertEquals("retried migration", String(store.read()!!))
    }

    @Test fun interruptedUpdatePreservesPreviousCommit() {
        base().writeText("old")
        File(base().path + ".new").writeText("partial")
        assertEquals("old", String(AtomicSnapshotFile(base()).read()!!))
    }

    @Test fun legacyBackupIsRecovered() {
        base().writeText("partial legacy write")
        File(base().path + ".bak").writeText("old")
        assertEquals("old", String(AtomicSnapshotFile(base()).read()!!))
    }

    @Test fun syncFailureBeforeCommitPreservesOldFile() {
        base().writeText("old")
        val store = AtomicSnapshotFile(base(), sync = { throw IOException("disk full") })
        assertThrows(IOException::class.java) { store.write("new".toByteArray()) }
        assertEquals("old", base().readText())
        assertFalse(File(base().path + ".new").exists())
    }

    @Test fun failedFirstWriteRemainsRetryable() {
        val store = AtomicSnapshotFile(base(), sync = { throw IOException("disk full") })
        assertThrows(IOException::class.java) { store.write("new".toByteArray()) }
        assertNull(store.read())
    }

    @Test fun verificationFailureNeverRollsBackCommittedFile() {
        base().writeText("old")
        val store = AtomicSnapshotFile(base(), verify = { _, _ -> throw IOException("transient read error") })
        assertThrows(IOException::class.java) { store.write("new".toByteArray()) }
        assertEquals("new", base().readText())
    }

    @Test fun verificationMismatchNeverDeletesOnlyCopy() {
        val store = AtomicSnapshotFile(base(), verify = { _, _ -> false })
        assertThrows(IllegalStateException::class.java) { store.write("new".toByteArray()) }
        assertEquals("new", base().readText())
    }
}
