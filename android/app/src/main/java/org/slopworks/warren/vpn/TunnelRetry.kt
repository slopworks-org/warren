package org.slopworks.warren.vpn

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive

internal suspend fun retryTunnel(
    desired: () -> Boolean,
    attempt: suspend () -> Unit,
    canRetry: () -> Boolean,
    wait: suspend (Long) -> Unit,
) {
    var backoff = 1000L
    while (currentCoroutineContext().isActive && desired()) {
        val failed = try {
            attempt()
            backoff = 1000L
            false
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            if (!canRetry()) return
            true
        }
        if (!desired()) return
        wait(backoff)
        if (failed) backoff = (backoff * 2).coerceAtMost(30_000)
    }
}
