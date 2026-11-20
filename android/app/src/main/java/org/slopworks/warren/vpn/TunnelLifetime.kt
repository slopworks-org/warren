package org.slopworks.warren.vpn

import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// Called on the main thread. The lock spans native teardown even when
// Android has already destroyed the service.
internal class TunnelLifetime {
    private val session = Mutex()
    private var active: Job? = null

    suspend fun <T> run(block: suspend () -> T): T = session.withLock {
        active = currentCoroutineContext().job
        try {
            block()
        } finally {
            active = null
        }
    }

    suspend fun replace(pause: () -> Unit, stopService: () -> Unit, commit: () -> Unit) {
        pause()
        active?.cancel()
        val stopped = runCatching(stopService)
        session.withLock {
            stopped.getOrThrow()
            commit()
        }
    }
}
