package com.hopae.eudi.wallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * A single ISO 18013-5 proximity presentation run. One-shot; the flow runs in
 * the wallet scope, drives the device-retrieval exchange over the transport, and pauses at
 * [ProximityState.RequestReceived] for the user's consent.
 */
class ProximitySession internal constructor(
    private val scope: CoroutineScope,
    private val flow: suspend ProximitySession.() -> Unit,
) {
    private val _state = MutableStateFlow<ProximityState>(ProximityState.GeneratingEngagement)
    val state: StateFlow<ProximityState> = _state.asStateFlow()

    private var job: Job? = null
    private var decision: CompletableDeferred<ProximitySelection?>? = null

    internal fun launch() {
        job = scope.launch {
            try {
                flow()
            } catch (e: WalletError.Proximity) {
                _state.value = ProximityState.Failed(e)
            } catch (e: Throwable) {
                _state.value = ProximityState.Failed(WalletError.Proximity.Unexpected(e))
            }
        }
    }

    internal fun emit(state: ProximityState) {
        _state.value = state
    }

    /** Pauses at [ProximityState.RequestReceived] for consent; returns the selection or null (declined). */
    internal suspend fun awaitDecision(request: ProximityRequest): ProximitySelection? {
        val deferred = CompletableDeferred<ProximitySelection?>()
        decision = deferred
        emit(ProximityState.RequestReceived(request))
        return deferred.await()
    }

    /** Approve with the chosen credentials — resumes the flow to build and send the DeviceResponse. */
    fun respond(selection: ProximitySelection) {
        decision?.complete(selection) ?: error("session is not awaiting a decision")
    }

    /** Decline the request — the flow terminates at [ProximityState.Declined]. */
    fun decline() {
        decision?.complete(null) ?: error("session is not awaiting a decision")
    }

    fun cancel() {
        job?.cancel()
    }
}
