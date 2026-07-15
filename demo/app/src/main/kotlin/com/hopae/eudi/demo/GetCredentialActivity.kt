@file:OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)

package com.hopae.eudi.demo

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.hopae.eudi.demo.ui.credTitle
import com.hopae.eudi.demo.ui.screens.claimPathLabel
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.ClaimCategory
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.android.dcapi.DcApiRequest
import com.hopae.eudi.wallet.android.dcapi.DcApiResult
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * Handles a Digital Credentials API (OpenID4VP / org-iso-mdoc) request routed to this wallet by the
 * Credential Manager. The UI-less plumbing — envelope parsing, origin, and result marshalling — lives in the
 * `com.hopae.eudi.android:dcapi` library (`DcApiRequest` / `DcApiResult`); this Activity owns the flow: show
 * the app's consent, drive the SDK, return the response.
 */
class GetCredentialActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val resultData = Intent()

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull()
        if (request == null || option == null) { finishError(resultData, "no digital credential request"); return }

        val origin = DcApiRequest.originOf(request, allowlist())
        LogStore.log("DC API request · origin=$origin · protocols=${DcApiRequest.protocolsOffered(option.requestJson)}")

        // The wallet assembles asynchronously (trust anchors from the trusted lists on first launch).
        lifecycleScope.launch {
            val wallet = DemoWallet.get(this@GetCredentialActivity)

            // org-iso-mdoc (ISO 18013-7): raw mdoc DeviceRequest → HPKE-encrypted DeviceResponse.
            val mdoc = DcApiRequest.matchProtocol(option.requestJson, listOf("org-iso-mdoc", "org.iso.mdoc"))
            if (mdoc != null) {
                val (proto, data) = mdoc
                val deviceReq = data.getString("deviceRequest")
                val encInfo = data.getString("encryptionInfo")
                runCatching {
                    // Resolve first: verify reader authentication (ISO 18013-5 §9.1.4) + list requested docs/claims.
                    val resolved = wallet.proximity.resolveDcApiMdoc(deviceReq, encInfo, origin)
                    val creds = runCatching { wallet.credentials.list().associateBy { it.id.value } }.getOrDefault(emptyMap())
                    val items = resolved.documents.map { doc ->
                        val cred = doc.candidates.firstOrNull()?.let { creds[it.value] }
                        val byId = (cred?.lifecycle as? Lifecycle.Issued)?.claims.orEmpty().associateBy { it.path.lastOrNull() }
                        val rows = doc.requestedElements.values.flatten().map { id ->
                            ClaimRow(claimPathLabel(listOf(id)), byId[id]?.value?.display() ?: "Shared")
                        }
                        ConsentItem(cred?.let { credTitle(it) } ?: doc.docType, rows)
                    }
                    // Reader auth is the ISO analogue of a signed request — surface its verdict (no WRPRC in raw mdoc).
                    val readerName = resolved.reader.commonName ?: origin
                    showConsent(DcApiVerifier(readerName, "In-app request", resolved.reader.trusted, registration = null), items,
                        onApprove = {
                            lifecycleScope.launch {
                                runCatching {
                                    val response = wallet.proximity.respondDcApiMdoc(deviceReq, encInfo, origin)
                                    DcApiResult.setResponse(resultData, DcApiResult.mdocResponseJson(proto, response))
                                    LogStore.log("✅ DC API (mdoc) response returned to caller")
                                    setResult(RESULT_OK, resultData)
                                }.onFailure { finishExceptionData(resultData, it.message) }
                                finish()
                            }
                        },
                        onDecline = { finishError(resultData, "declined by user") })
                }.onFailure { finishError(resultData, it.message) }
                return@launch
            }

            // Match the OpenID4VP request AND capture its protocol identifier — the response envelope must echo it.
            val vp = DcApiRequest.matchProtocol(
                option.requestJson,
                listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed", "openid4vp-v1-multisigned"),
            )
            if (vp == null) { finishError(resultData, "no openid4vp request"); return@launch }
            val (vpProtocol, vpData) = vp

            runCatching {
                val session = wallet.presentation.startDcApi(vpData.toString(), origin)
                val resolved = session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }
                if (resolved is PresentationState.Failed) throw resolved.error
                val presentation = (resolved as PresentationState.RequestResolved).request
                LogStore.log("DC API verifier=${presentation.verifier.clientId} · satisfiable=${presentation.satisfiable}")
                val creds = runCatching { wallet.credentials.list().associateBy { it.id.value } }.getOrDefault(emptyMap())
                val items = presentation.queries.map { q ->
                    val cand = q.candidates.firstOrNull()
                    val cred = cand?.let { creds[it.credentialId.value] }
                    val disc = cand?.disclosedPaths?.toSet().orEmpty()
                    val rows = (cred?.lifecycle as? Lifecycle.Issued)?.claims.orEmpty()
                        .filter { it.category == ClaimCategory.Subject && disc.any { d -> d.size <= it.path.size && it.path.subList(0, d.size) == d } }
                        .map { ClaimRow(claimPathLabel(it.path), it.value.display()) }
                    ConsentItem(cred?.let { credTitle(it) } ?: q.queryId, rows)
                }
                val v = presentation.verifier
                val reg = v.registration
                val rpName = reg?.subjectName ?: reg?.subject?.takeIf { it.isNotBlank() } ?: v.commonName ?: v.clientId
                val subtitle = reg?.intermediaryName?.let { "via $it" } ?: "In-app request"
                val regInfo = reg?.let { r ->
                    val sigOk = r.attested || r.registrarVerified
                    val (text, ok) = when {
                        !sigOk -> "Self-declared" to false
                        r.statusValid == false -> "Revoked" to false
                        else -> "Verified by registrar" to true
                    }
                    val purpose = r.purpose.takeIf { it.isNotEmpty() }?.let { p ->
                        val lang = Locale.getDefault().language
                        (p.firstOrNull { it.lang.startsWith(lang, true) } ?: p.first()).value
                    }
                    DcApiRegInfo(text, ok, purpose, r.unregisteredClaims.isNotEmpty())
                }
                showConsent(DcApiVerifier(rpName, subtitle, v.trusted, regInfo), items,
                    onApprove = {
                        lifecycleScope.launch {
                            runCatching {
                                session.respond(PresentationSelection.auto(presentation))
                                when (val done = session.state.first { it.isTerminal }) {
                                    is PresentationState.Completed -> returnDcApiResponse(resultData, vpProtocol, done.dcApiResponse)
                                    is PresentationState.Failed -> throw done.error
                                    else -> error("unexpected terminal state $done")
                                }
                            }.onFailure { finishError(resultData, it.message) }
                        }
                    },
                    onDecline = { finishError(resultData, "declined by user") })
            }.onFailure { finishError(resultData, it.message) }
        }
    }

    private fun returnDcApiResponse(resultData: Intent, protocol: String, response: String?) {
        runCatching {
            val body = response ?: error("no DC API response produced")
            // Wrap the SDK's inner response ({vp_token}|{response:<JWE>}) in the `{protocol, data}` envelope the
            // platform expects, echoing the matched request protocol — recent Chrome rejects a response without a
            // top-level `protocol` ("No value for protocol"). The mdoc path builds the same envelope.
            DcApiResult.setResponse(resultData, DcApiResult.openId4VpResponseJson(protocol, body))
            LogStore.log("✅ DC API response returned to caller")
            setResult(RESULT_OK, resultData)
        }.onFailure { finishExceptionData(resultData, it.message) }
        finish()
    }

    private fun showConsent(verifier: DcApiVerifier, items: List<ConsentItem>, onApprove: () -> Unit, onDecline: () -> Unit) {
        setContent { WalletTheme { DcApiConsentSheet(verifier, items, onApprove, onDecline) } }
    }

    /** The app-owned privileged-caller allowlist (which browsers may present a web origin). */
    private fun allowlist(): String = runCatching {
        assets.open("privileged_allowlist.json").bufferedReader().use { it.readText() }
    }.getOrDefault("""{"apps":[]}""")

    private fun finishError(resultData: Intent, message: String?) { finishExceptionData(resultData, message); finish() }

    private fun finishExceptionData(resultData: Intent, message: String?) {
        LogStore.log("❌ DC API: ${message ?: "error"}")
        DcApiResult.setError(resultData, message)
        setResult(RESULT_OK, resultData)
    }
}
