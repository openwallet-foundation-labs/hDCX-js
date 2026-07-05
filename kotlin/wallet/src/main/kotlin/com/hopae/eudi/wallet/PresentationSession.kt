package com.hopae.eudi.wallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * A single presentation run driven as a state machine. One-shot; the flow runs
 * in the wallet scope and pauses at [PresentationState.RequestResolved] for the user's consent.
 */
class PresentationSession internal constructor(
    private val scope: CoroutineScope,
    private val flow: suspend PresentationSession.() -> Unit,
) {
    private val _state = MutableStateFlow<PresentationState>(PresentationState.ResolvingRequest)
    val state: StateFlow<PresentationState> = _state.asStateFlow()

    private var job: Job? = null
    private var decision: CompletableDeferred<PresentationSelection?>? = null

    internal fun launch() {
        job = scope.launch {
            try {
                flow()
            } catch (e: WalletError.Presentation) {
                _state.value = PresentationState.Failed(e)
            } catch (e: Throwable) {
                _state.value = PresentationState.Failed(WalletError.Presentation.Unexpected(e))
            }
        }
    }

    internal fun emit(state: PresentationState) {
        _state.value = state
    }

    /** Pauses at [PresentationState.RequestResolved] for consent; returns the selection or null (declined). */
    internal suspend fun awaitDecision(request: PresentationRequest): PresentationSelection? {
        val deferred = CompletableDeferred<PresentationSelection?>()
        decision = deferred
        emit(PresentationState.RequestResolved(request))
        return deferred.await()
    }

    /** Approve with the chosen credentials — resumes the flow to submit the response. */
    fun respond(selection: PresentationSelection) {
        decision?.complete(selection) ?: error("session is not awaiting a decision")
    }

    /** Decline the request — the flow terminates at [PresentationState.Declined]. */
    fun decline() {
        decision?.complete(null) ?: error("session is not awaiting a decision")
    }

    fun cancel() {
        job?.cancel()
    }
}
