package com.hopae.eudi.demo

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Carries an offer / presentation deep link (e.g. `haip-vp://…`, `openid-credential-offer://…`) from
 * [MainActivity] into the Compose UI, which processes it the same way as a scanned QR.
 */
object IncomingLink {
    private val _flow = MutableStateFlow<String?>(null)
    val flow: StateFlow<String?> = _flow

    fun post(uri: String) { _flow.value = uri }
    fun consume() { _flow.value = null }
}
