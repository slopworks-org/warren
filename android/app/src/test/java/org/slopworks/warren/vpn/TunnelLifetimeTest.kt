package org.slopworks.warren.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class TunnelLifetimeTest {
    @Test
    fun failedStopSignalStillClosesOldWorkerAndKeepsReceiptForRetry() = runBlocking {
        withTimeout(5000) {
            val record = Replacement()
            val lifetime = TunnelLifetime()
            val entered = CompletableDeferred<Unit>()
            val closing = CompletableDeferred<Unit>()
            val finishClose = CompletableDeferred<Unit>()
            val worker = launch {
                lifetime.run {
                    entered.complete(Unit)
                    try {
                        awaitCancellation()
                    } finally {
                        withContext(NonCancellable) {
                            closing.complete(Unit)
                            finishClose.await()
                            record.forwarding = false
                        }
                    }
                }
            }
            entered.await()
            val fault = IOException("stop dispatch failed")
            val first = async {
                runCatching { lifetime.replace(record::pause, { throw fault }, record::commit) }
            }
            try {
                closing.await()
                assertTrue(record.forwarding)
                assertFalse(first.isCompleted)
                record.assertPendingOld()
            } finally {
                finishClose.complete(Unit)
            }
            assertSame(fault, first.await().exceptionOrNull())
            worker.join()
            assertFalse(record.forwarding)
            record.assertPendingOld()

            // The Android service may still be bound, with no worker to stop.
            lifetime.replace(record::pause, {}, record::commit)
            assertEquals("new", record.current)
            assertFalse(record.pending)
            assertFalse(record.desired)
        }
    }

    @Test
    fun interruptedReplacementAndFailedCommitRetainStoppedOldIdentityAndReceipt() = runBlocking {
        withTimeout(5000) {
            val record = Replacement()
            val oldProcess = TunnelLifetime()
            val entered = CompletableDeferred<Unit>()
            val stopping = CompletableDeferred<Unit>()
            val finishClose = CompletableDeferred<Unit>()
            val worker = launch {
                oldProcess.run {
                    entered.complete(Unit)
                    try {
                        awaitCancellation()
                    } finally {
                        withContext(NonCancellable) {
                            finishClose.await()
                            record.forwarding = false
                        }
                    }
                }
            }
            entered.await()
            val replacement = launch {
                oldProcess.replace(record::pause, { stopping.complete(Unit) }, record::commit)
            }
            try {
                stopping.await()
                replacement.cancelAndJoin()
                record.assertPendingOld()
            } finally {
                finishClose.complete(Unit)
            }
            worker.join()

            val restarted = TunnelLifetime()
            val diskFault = IOException("atomic install failed")
            val failed = runCatching { restarted.replace(record::pause, {}, { throw diskFault }) }
            assertSame(diskFault, failed.exceptionOrNull())
            assertFalse(record.forwarding)
            record.assertPendingOld()
            restarted.replace(record::pause, {}, record::commit)
            assertEquals("new", record.current)
            assertFalse(record.pending)
            assertFalse(record.desired)
        }
    }

    private class Replacement {
        var current = "old"
            private set
        var desired = true
            private set
        var pending = true
            private set
        var forwarding = true

        fun pause() {
            assertTrue(pending)
            desired = false
        }

        fun commit() {
            assertFalse(forwarding)
            assertTrue(pending)
            current = "new"
            pending = false
        }

        fun assertPendingOld() {
            assertEquals("old", current)
            assertFalse(desired)
            assertTrue(pending)
        }
    }
}
