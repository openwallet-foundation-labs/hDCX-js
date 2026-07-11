package com.hopae.eudi.wallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * A single issuance run driven as a state machine. One-shot; the flow runs in
 * the wallet scope and pauses at browser-authorization / tx-code interruptions until the app resumes.
 */
class IssuanceSession internal constructor(
    private val scope: CoroutineScope,
    private val flow: suspend IssuanceSession.() -> Unit,
) {
    private val _state = MutableStateFlow<IssuanceState>(IssuanceState.Preparing)
    val state: StateFlow<IssuanceState> = _state.asStateFlow()

    private var job: Job? = null
    private var authContinuation: CompletableDeferred<String>? = null
    private var txCodeContinuation: CompletableDeferred<String>? = null

    /** The credential issuer, set by the flow as soon as it is known, so a failure can be logged against it. */
    internal var issuer: String? = null

    internal fun launch() {
        job = scope.launch {
            try {
                flow()
            } catch (e: WalletError.Issuance) {
                _state.value = IssuanceState.Failed(e)
            } catch (e: Throwable) {
                _state.value = IssuanceState.Failed(WalletError.Issuance.Unexpected(e))
            }
        }
    }

    internal fun emit(state: IssuanceState) {
        _state.value = state
    }

    /** Pauses the flow at [IssuanceState.AuthorizationRequired] until [completeAuthorization]. */
    internal suspend fun awaitAuthorization(url: String): String {
        val deferred = CompletableDeferred<String>()
        authContinuation = deferred
        emit(IssuanceState.AuthorizationRequired(url))
        return deferred.await()
    }

    /** Pauses the flow at [IssuanceState.TxCodeRequired] until [submitTxCode]. */
    internal suspend fun awaitTxCode(txCode: TxCodeSpec?): String {
        val deferred = CompletableDeferred<String>()
        txCodeContinuation = deferred
        emit(IssuanceState.TxCodeRequired(txCode))
        return deferred.await()
    }

    /** Resume after the browser authorization step (auth-code flow). */
    fun completeAuthorization(redirectUri: String) {
        authContinuation?.complete(redirectUri) ?: error("session is not awaiting authorization")
    }

    /** Provide the transaction code when the session is [IssuanceState.TxCodeRequired]. */
    fun submitTxCode(code: String) {
        txCodeContinuation?.complete(code) ?: error("session is not awaiting a transaction code")
    }

    fun cancel() {
        job?.cancel()
    }
}
