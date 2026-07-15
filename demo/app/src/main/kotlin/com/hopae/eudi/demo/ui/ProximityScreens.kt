package com.hopae.eudi.demo.ui

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Build
import android.util.Base64
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.StartOffset
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Nfc
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import com.hopae.eudi.demo.security.BiometricAuth
import com.hopae.eudi.demo.security.WalletSecurity
import com.hopae.eudi.demo.ui.components.DocTile
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.components.SecondaryButton
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustBadge
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.components.absorbTouches
import com.hopae.eudi.demo.ui.screens.Centered
import com.hopae.eudi.demo.ui.screens.GroupHeader
import com.hopae.eudi.demo.ui.screens.PresentDeclined
import com.hopae.eudi.demo.ui.screens.PresentDone
import com.hopae.eudi.demo.ui.screens.PresentFailed
import com.hopae.eudi.demo.ui.screens.PresentProgress
import com.hopae.eudi.demo.ui.screens.claimPathLabel
import com.hopae.eudi.demo.ui.theme.WalletTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.RequestedDocumentView
import com.google.zxing.BarcodeFormat
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.PortraitCaptureActivity
import com.hopae.eudi.demo.security.AppLock
import android.app.Activity
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.wallet.android.proximity.Ble
import com.hopae.eudi.wallet.android.proximity.BleGattClientTransport
import com.hopae.eudi.wallet.android.proximity.BleGattServerTransport
import com.hopae.eudi.wallet.android.proximity.NfcEngagementService
import com.hopae.eudi.wallet.android.proximity.NfcReader
import com.hopae.eudi.wallet.proximity.MdocNfcEngagement
import com.hopae.eudi.wallet.proximity.NfcEngagementProcessor
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import kotlinx.coroutines.flow.first
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.ProximityTransport
import java.util.UUID
import com.hopae.eudi.wallet.ProximityRequest
import com.hopae.eudi.wallet.ProximitySelection
import com.hopae.eudi.wallet.ProximitySession
import com.hopae.eudi.wallet.ProximityState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.RequestedDocument
import com.hopae.eudi.wallet.mdoc.VerifiedDocument
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

private val BLE_PERMISSIONS: Array<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
    arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

/** What the reader requests — the PID (mdoc); the holder answers if it holds a matching mdoc credential. */
private fun readerRequest() = listOf(
    RequestedDocument(
        "eu.europa.ec.eudi.pid.1",
        mapOf("eu.europa.ec.eudi.pid.1" to listOf("family_name", "given_name", "birth_date", "nationality")),
    ),
)

/** Holder present flow phases: waiting for a reader → reviewing its request → sending → terminal. */
private enum class ProxPhase { Engaging, Consent, Sending, Done, Declined, Failed }

// ---------- Holder: present an mdoc over BLE (this device is the wallet) ----------

@Composable
fun ProximityHolderDialog(wallet: Wallet, onClose: () -> Unit) {
    val context = LocalContext.current
    var status by remember { mutableStateOf("Preparing…") }
    var qr by remember { mutableStateOf<Bitmap?>(null) }
    // Top-level engagement kind (QR vs NFC), remembered across sessions; the peripheral/central and
    // static/negotiated variants come from Settings. `mode` (0..3) is derived from the two.
    var kind by remember { mutableStateOf(ProximityPrefs.kind(context)) }
    val bleCentral = remember { ProximityPrefs.bleCentral(context) }
    val nfcNegotiatedPref = remember { ProximityPrefs.nfcNegotiated(context) }
    val mode = when (kind) {
        ProximityPrefs.NFC -> if (nfcNegotiatedPref) 3 else 2
        else -> if (bleCentral) 1 else 0
    }
    var session by remember { mutableStateOf<ProximitySession?>(null) }
    var pending by remember { mutableStateOf<ProximityRequest?>(null) } // reader's request, awaiting the user's consent
    var phase by remember { mutableStateOf(ProxPhase.Engaging) }
    var errMsg by remember { mutableStateOf<String?>(null) }
    var credsById by remember { mutableStateOf<Map<String, Credential>>(emptyMap()) }
    LaunchedEffect(Unit) { credsById = runCatching { wallet.credentials.list().associateBy { it.id.value } }.getOrDefault(emptyMap()) }
    var granted by remember { mutableStateOf(BLE_PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }
    val btAdapter = remember { context.getSystemService(BluetoothManager::class.java)?.adapter }
    var btOn by remember { mutableStateOf(btAdapter?.isEnabled == true) }
    // Presenting starts a GATT server, which needs Bluetooth actually on — not just permission granted.
    val enableBtLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { btOn = btAdapter?.isEnabled == true }

    DisposableEffect(granted, btOn, mode) {
        if (!granted) {
            status = "Grant Bluetooth permission to present"
            permLauncher.launch(BLE_PERMISSIONS)
            return@DisposableEffect onDispose {}
        }
        if (btAdapter == null) {
            status = "Bluetooth unavailable on this device"
            return@DisposableEffect onDispose {}
        }
        if (!btOn) {
            status = "Turn on Bluetooth to present"
            AppLock.suppressResumeLock() // the enable-Bluetooth system activity shouldn't demand a re-unlock
            enableBtLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
            return@DisposableEffect onDispose {}
        }
        qr = null
        pending = null
        errMsg = null
        phase = ProxPhase.Engaging
        val central = mode == 1
        val nfc = mode == 2 || mode == 3
        val negotiated = mode == 3
        // NFC: win the HCE routing conflict while presenting (other wallets register the same NDEF AID).
        if (nfc) (context as? android.app.Activity)?.let { NfcEngagementService.requestForeground(it) }
        val uuid = UUID.randomUUID()
        val uuidBytes = Ble.uuidToBytes(uuid)
        val scope = CoroutineScope(Dispatchers.Main)
        // Peripheral server mode / NFC → we're the GATT server. Central client mode → we're the GATT client (the
        // reader advertises our UUID); scan for it in parallel. NFC delivers the engagement via HCE (no QR).
        val server = if (central) null else BleGattServerTransport(context, uuid, Ble.PERIPHERAL_SERVER, if (nfc) emptyList() else listOf(DeviceEngagement.bleRetrievalMethod(peripheralServerUuid = uuidBytes)), logger = LogWalletLogger())
        val client = if (central) BleGattClientTransport(context, uuid, Ble.CENTRAL_CLIENT, listOf(DeviceEngagement.bleRetrievalMethod(centralClientUuid = uuidBytes)), logger = LogWalletLogger()) else null
        val transport: ProximityTransport = server ?: client!!
        // Shared teardown — used on a start() failure and on normal dispose.
        val cleanup = {
            NfcEngagementService.processor = null
            if (nfc) (context as? android.app.Activity)?.let { NfcEngagementService.releaseForeground(it) }
            scope.cancel(); server?.stop(); client?.stop()
        }
        // Starting the GATT server can throw if Bluetooth flips off between the check and here — catch it
        // instead of letting it crash the app from this DisposableEffect body (runs on the main thread).
        try {
            server?.start()
        } catch (e: Throwable) {
            status = "❌ ${e.message}"
            LogStore.log("❌ Proximity holder: ${e.message}")
            return@DisposableEffect onDispose { cleanup() }
        }
        if (client != null) scope.launch { runCatching { client.connect() } }

        // Drive one presentation session's state → engagement display, consent, and completion UI.
        suspend fun driveSession(s: ProximitySession) {
            session = s
            s.state.collect { st ->
                when (st) {
                    is ProximityState.EngagementReady -> {
                        // Central client mode: arm Ident verification now that the engagement (EDeviceKey) exists.
                        client?.armIdent(DeviceEngagement.eDeviceKeyBytes(st.deviceEngagement))
                        val ndef = st.handoverNdef
                        when {
                            ndef == null -> { qr = encodeQr("mdoc:" + b64(st.deviceEngagement)); status = "Waiting for a reader — show this QR" }
                            !negotiated -> { NfcEngagementService.processor = NfcEngagementProcessor(staticHandoverSelect = ndef); qr = null; status = "Tap your phone to the reader" }
                            else -> { qr = null; status = "Negotiating over NFC…" } // negotiated: the processor is already armed
                        }
                        phase = ProxPhase.Engaging
                    }
                    is ProximityState.RequestReceived -> {
                        pending = st.request // ask the user before sending (like OpenID4VP consent)
                        phase = ProxPhase.Consent
                        status = "Reader connected — review the request"
                        LogStore.log("Proximity: reader requested ${st.request.documents.size} doc(s); awaiting consent")
                    }
                    ProximityState.Submitting -> { pending = null; phase = ProxPhase.Sending; status = "Sending response…" }
                    ProximityState.Completed -> { pending = null; phase = ProxPhase.Done; status = "✅ Presented to the reader"; LogStore.log("✅ Proximity presented") }
                    ProximityState.Declined -> { pending = null; phase = ProxPhase.Declined; status = "Declined" }
                    is ProximityState.Failed -> { pending = null; errMsg = st.error.message; phase = ProxPhase.Failed; status = "❌ ${st.error.message}" }
                    else -> {}
                }
            }
        }

        if (negotiated) {
            // Negotiated handover (§8.2.2.1): the reader runs the TNEP exchange and writes its Handover Request;
            // only then do we start presenting (binding [Hs, Hr]) and hand the Handover Select back over NFC.
            NfcEngagementService.processor = NfcEngagementProcessor(
                negotiatedHandoverSelect = { hr ->
                    val s = wallet.proximity.present(transport, nfc = true, handoverRequestNdef = hr)
                    scope.launch { runCatching { driveSession(s) } }
                    val ready = s.state.first { it is ProximityState.EngagementReady || it is ProximityState.Failed }
                    if (ready is ProximityState.Failed) throw ready.error
                    (ready as ProximityState.EngagementReady).handoverNdef ?: error("no Handover Select produced")
                },
            )
            status = "Tap your phone to the reader (negotiated)"
        } else {
            scope.launch {
                try {
                    driveSession(wallet.proximity.present(transport, nfc = nfc))
                } catch (e: kotlin.coroutines.cancellation.CancellationException) {
                    throw e // normal teardown when the mode changes or the dialog closes — not a failure
                } catch (e: Throwable) {
                    status = "❌ ${e.message}"
                    LogStore.log("❌ Proximity holder: ${e.message}")
                }
            }
        }
        onDispose { cleanup() }
    }

    val c = WalletTheme.colors
    val activity = context as? FragmentActivity
    fun decline() { session?.decline(); phase = ProxPhase.Declined }
    fun share(sel: ProximitySelection) {
        val s = session ?: return
        val go = { s.respond(sel); phase = ProxPhase.Sending }
        val useBio = activity != null && WalletSecurity.biometricEnabled(context) && BiometricAuth.canUse(activity)
        if (useBio) BiometricAuth.prompt(activity, "Confirm sharing", "Verify to share with the reader", onSuccess = { go() }, negativeText = "Cancel")
        else go()
    }
    fun back() { if (phase == ProxPhase.Consent) decline() else onClose() }
    BackHandler { back() }

    val topInset = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    val bottomInset = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
    Column(
        Modifier.fillMaxSize().background(c.screen).absorbTouches()
            .padding(start = 20.dp, end = 20.dp, top = topInset + 12.dp, bottom = bottomInset + 20.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(36.dp).clip(RoundedCornerShape(99.dp)).background(c.card).clickable { back() },
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = c.ink, modifier = Modifier.size(18.dp)) }
            Spacer(Modifier.width(10.dp))
            Text("Present in person", style = MaterialTheme.typography.titleMedium, color = c.ink)
        }
        Spacer(Modifier.height(16.dp))
        Box(Modifier.weight(1f).fillMaxWidth()) {
            val req = pending
            val onKind: (Int) -> Unit = { k -> kind = k; ProximityPrefs.setKind(context, k) }
            when (phase) {
                ProxPhase.Consent ->
                    if (req != null) ProximityReview(req, credsById, onShare = { share(it) }, onDecline = { decline() })
                    else ProximityEngagement(kind, onKind, qr, status)
                ProxPhase.Sending -> Centered { PresentProgress("Sharing…", "Sending your data to the reader.") }
                ProxPhase.Done -> Centered { PresentDone("Shared", "The reader received your data.", onDone = onClose) }
                ProxPhase.Declined -> Centered { PresentDeclined("Nothing was shared with the reader.", onClose) }
                ProxPhase.Failed -> Centered { PresentFailed("Couldn't share", errMsg ?: "The presentation failed.", onClose = onClose) }
                ProxPhase.Engaging -> ProximityEngagement(kind, onKind, qr, status)
            }
        }
    }
}

/** Waiting-for-a-reader screen: the engagement QR (or NFC prompt) and a QR / NFC choice. */
@Composable
private fun ProximityEngagement(kind: Int, onKind: (Int) -> Unit, qr: Bitmap?, status: String) {
    val c = WalletTheme.colors
    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                if (qr != null) {
                    WalletCard(Modifier.size(280.dp)) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Image(qr.asImageBitmap(), "engagement QR", Modifier.size(240.dp))
                        }
                    }
                    Text(status, style = MaterialTheme.typography.bodyMedium, color = c.inkBody)
                } else {
                    NfcPulse()
                    Text(status, style = MaterialTheme.typography.titleSmall, color = c.ink)
                }
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            KindChip(kind == ProximityPrefs.QR, "QR") { onKind(ProximityPrefs.QR) }
            KindChip(kind == ProximityPrefs.NFC, "NFC") { onKind(ProximityPrefs.NFC) }
        }
    }
}

/** An NFC icon with concentric rings rippling outward — the "tap your phone" cue while waiting over NFC. */
@Composable
private fun NfcPulse() {
    val c = WalletTheme.colors
    val t = rememberInfiniteTransition(label = "nfc")
    val r1 by t.animateFloat(0f, 1f, infiniteRepeatable(tween(2000, easing = LinearEasing), RepeatMode.Restart, StartOffset(0)), "r1")
    val r2 by t.animateFloat(0f, 1f, infiniteRepeatable(tween(2000, easing = LinearEasing), RepeatMode.Restart, StartOffset(666)), "r2")
    val r3 by t.animateFloat(0f, 1f, infiniteRepeatable(tween(2000, easing = LinearEasing), RepeatMode.Restart, StartOffset(1333)), "r3")
    Box(Modifier.size(220.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val maxR = size.minDimension / 2f
            val minR = 34.dp.toPx()
            val stroke = 2.5.dp.toPx()
            listOf(r1, r2, r3).forEach { p ->
                drawCircle(color = c.brand, radius = minR + (maxR - minR) * p, alpha = (1f - p) * 0.6f, style = Stroke(width = stroke))
            }
        }
        Box(Modifier.size(68.dp).clip(RoundedCornerShape(99.dp)).background(c.brand), contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Nfc, null, tint = Color.White, modifier = Modifier.size(34.dp))
        }
    }
}

@Composable
private fun RowScope.KindChip(selected: Boolean, label: String, onClick: () -> Unit) {
    val c = WalletTheme.colors
    val shape = RoundedCornerShape(12.dp)
    Box(
        Modifier.weight(1f).clip(shape)
            .background(if (selected) c.brand else c.card)
            .border(1.dp, if (selected) c.brand else c.cardBorderStrong, shape)
            .clickable { onClick() }.padding(vertical = 14.dp),
        contentAlignment = Alignment.Center,
    ) { Text(label, style = MaterialTheme.typography.labelLarge, color = if (selected) Color.White else c.ink) }
}

/** Consent for an in-person reader's request — reader trust + shared/not-shared attributes + Share/Decline. */
@Composable
private fun ProximityReview(req: ProximityRequest, credsById: Map<String, Credential>, onShare: (ProximitySelection) -> Unit, onDecline: () -> Unit) {
    val c = WalletTheme.colors
    val reader = req.reader
    // The holder's chosen credential per requested doctype (defaults to the first candidate).
    val chosen = remember(req) {
        mutableStateMapOf<String, CredentialId>().apply {
            req.documents.forEach { d -> d.candidates.firstOrNull()?.let { put(d.docType, it) } }
        }
    }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            // Reader
            WalletCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Box(Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(c.ink), contentAlignment = Alignment.Center) {
                        Text((reader.commonName ?: "R").take(1).uppercase(), color = Color.White, style = MaterialTheme.typography.titleMedium)
                    }
                    Column(Modifier.weight(1f)) {
                        Text(reader.commonName ?: "In-person reader", style = MaterialTheme.typography.titleSmall, color = c.ink)
                        Text("ISO 18013-5 · in person", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
                    }
                    TrustBadge(reader.trusted, trustedText = "Verified", untrustedText = "Unverified")
                }
            }
            // Trust — reader authentication only (no OpenID4VP registration in proximity).
            SectionLabel("Trust")
            WalletCard(padding = PaddingValues(0.dp)) {
                TrustRow("Reader authentication", if (reader.trusted) "Verified" else "Not verified", reader.trusted)
            }
            // Shared attributes per requested document.
            SectionLabel("You'll share")
            req.documents.forEach { ProximityDocCard(it, credsById, chosen) }
            Text("Only the shown attributes are shared. Your full documents never leave this device.", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            SecondaryButton("Decline", onDecline, Modifier.weight(1f))
            PrimaryButton("Share", { onShare(ProximitySelection(chosen.toMap())) }, Modifier.weight(1.5f), enabled = req.satisfiable)
        }
    }
}

@Composable
private fun ProximityDocCard(doc: RequestedDocumentView, credsById: Map<String, Credential>, chosen: MutableMap<String, CredentialId>) {
    val c = WalletTheme.colors
    val selectedId = chosen[doc.docType] ?: doc.candidates.firstOrNull()
    val cred = selectedId?.let { credsById[it.value] }
    val title = cred?.let { credTitle(it) } ?: docTypeLabel(doc.docType)
    val requested = doc.requestedElements.flatMap { (ns, els) -> els.map { listOf(ns, it) } }
    val valueByPath = (cred?.lifecycle as? Lifecycle.Issued)?.claims.orEmpty().associate { it.path to it.value }

    WalletCard(padding = PaddingValues(0.dp)) {
        Row(Modifier.fillMaxWidth().padding(16.dp, 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall, color = if (cred != null) c.ink else c.inkFaint)
                Text(if (cred != null) "Required" else "No matching document", style = MaterialTheme.typography.bodySmall, color = if (cred != null) c.inkMuted else c.danger)
            }
        }

        // Credential picker when more than one stored document answers this doctype — pick which one to present.
        if (doc.candidates.size > 1) {
            Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
            Spacer(Modifier.height(8.dp))
            GroupHeader("Choose a document")
            doc.candidates.forEach { candId ->
                val candCred = credsById[candId.value]
                val candValues = (candCred?.lifecycle as? Lifecycle.Issued)?.claims.orEmpty().associate { it.path to it.value }
                val subtitle = requested.mapNotNull { candValues[it]?.display() }.filter { it.isNotBlank() }.take(2).joinToString(" · ")
                ProxCandidateCard(candCred, candId == selectedId, subtitle) { chosen[doc.docType] = candId }
            }
            Spacer(Modifier.height(6.dp))
        }

        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
        GroupHeader("Shared")
        // Only the requested elements the chosen document actually holds are sent (ISO 18013-5 partial
        // disclosure): a reader may ask for more, but absent elements are simply omitted — so we list exactly
        // what will leave the device, with its value, rather than showing a requested-but-absent "—".
        val shared = requested.filter { valueByPath.containsKey(it) }
        if (shared.isEmpty()) {
            Text("No matching attributes in this document.", style = MaterialTheme.typography.bodySmall, color = c.inkMuted, modifier = Modifier.padding(16.dp, 6.dp, 16.dp, 12.dp))
        } else {
            shared.forEach { path -> InfoRow(claimPathLabel(path), valueByPath.getValue(path).display()) }
        }
    }
}

/** A colored, selectable credential card for the proximity document picker (radio single-pick). */
@Composable
private fun ProxCandidateCard(cred: Credential?, checked: Boolean, subtitle: String, onClick: () -> Unit) {
    val c = WalletTheme.colors
    val shape = RoundedCornerShape(12.dp)
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 5.dp).clip(shape)
            .background(if (checked) c.brand.copy(alpha = 0.06f) else c.card)
            .border(if (checked) 1.5.dp else 1.dp, if (checked) c.brand else c.cardBorder, shape)
            .clickable { onClick() }.padding(10.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (cred != null) DocTile(credGlyph(cred), credGradient(cred), size = 40)
        Column(Modifier.weight(1f)) {
            Text(cred?.let { credTitle(it) } ?: "Credential", style = MaterialTheme.typography.titleSmall, color = c.ink)
            if (subtitle.isNotBlank()) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        Box(
            Modifier.size(20.dp).clip(RoundedCornerShape(99.dp))
                .border(2.dp, if (checked) c.brand else c.cardBorderStrong, RoundedCornerShape(99.dp))
                .background(if (checked) c.brand else Color.Transparent),
            contentAlignment = Alignment.Center,
        ) { if (checked) Icon(Icons.Filled.Check, null, tint = Color.White, modifier = Modifier.size(12.dp)) }
    }
}

/** Friendly label for a bare mdoc doctype when no matching credential is held to name it. */
private fun docTypeLabel(docType: String): String = when {
    docType.contains("pid", true) -> "Personal ID"
    docType.contains("mdl", true) || docType.contains("18013.5.1", true) -> "Mobile Driving Licence"
    else -> docType.substringAfterLast('.').replace('_', ' ').replaceFirstChar { it.uppercase() }
}

// ---------- Reader: scan a wallet's QR and read its mdoc over BLE (this device is the verifier) ----------

@Composable
fun ProximityReaderScreen(wallet: Wallet) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("Scan a wallet's QR or tap it over NFC to read its mdoc.") }
    var results by remember { mutableStateOf<List<VerifiedDocument>>(emptyList()) }
    var nfcWaiting by remember { mutableStateOf(false) } // waiting for the NFC tap → show the pulse
    var nfcJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    var granted by remember { mutableStateOf(BLE_PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }
    // Reading needs Bluetooth actually on — not just permission granted — else the BLE scan silently times out.
    val btAdapter = remember { context.getSystemService(BluetoothManager::class.java)?.adapter }
    val enableBtLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {}

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: run { status = "Scan cancelled"; return@rememberLauncherForActivityResult }
        val engagement = decodeEngagement(content) ?: run { status = "❌ Not an mdoc proximity QR"; return@rememberLauncherForActivityResult }
        val ble = DeviceEngagement.parseBle(engagement) ?: run { status = "❌ Engagement carries no BLE method"; return@rememberLauncherForActivityResult }
        results = emptyList()
        status = "Connecting over BLE…"
        scope.launch {
            try {
                // Match the holder's mode: peripheral server → we're the GATT client; central client → we're the GATT server.
                val peripheral = ble.peripheralServerUuid
                val central = ble.centralClientUuid
                val transport: ProximityTransport = when {
                    peripheral != null -> BleGattClientTransport(context, Ble.bytesToUuid(peripheral), Ble.PERIPHERAL_SERVER, logger = LogWalletLogger()).also { it.connect() }
                    // Central client mode: we're the GATT server → expose the Ident characteristic (§8.3.3.1.1.4).
                    central != null -> BleGattServerTransport(context, Ble.bytesToUuid(central), Ble.CENTRAL_CLIENT, identKey = DeviceEngagement.eDeviceKeyBytes(engagement), logger = LogWalletLogger()).also { it.start() }
                    else -> { status = "❌ Engagement carries no BLE UUID"; return@launch }
                }
                status = "Requesting documents…"
                val docs = wallet.reader.read(transport, engagement, readerRequest())
                results = docs
                status = if (docs.isEmpty()) "No documents returned" else "✅ Read ${docs.size} document(s)"
                LogStore.log("Reader read ${docs.size} document(s) over BLE")
            } catch (e: Throwable) {
                status = "❌ ${e.message}"
                LogStore.log("❌ Reader: ${e.message}")
            }
        }
    }

    val c = WalletTheme.colors
    // Gate an action on BLE permission + Bluetooth being on; prompt for whichever is missing (like the holder).
    fun ensureReady(action: () -> Unit) {
        if (!granted) { permLauncher.launch(BLE_PERMISSIONS); return }
        if (btAdapter == null) { status = "Bluetooth is unavailable on this device"; return }
        if (!btAdapter.isEnabled) {
            status = "Turn on Bluetooth to read"
            AppLock.suppressResumeLock() // the enable-Bluetooth system activity shouldn't demand a re-unlock
            enableBtLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
            return
        }
        action()
    }
    // Check BLE readiness the moment the screen opens (i.e. when the Home "Reader" button is pressed), so a
    // missing permission / disabled Bluetooth is prompted up front instead of surfacing as a silent timeout.
    LaunchedEffect(Unit) { ensureReady {} }

    fun onNfc() {
        results = emptyList()
        status = "Hold your phone to the wallet…"
        nfcWaiting = true
        nfcJob = scope.launch {
            try {
                val handover = NfcReader.readHandover(context as Activity)
                nfcWaiting = false // tap received — the NFC handover is done, the rest is BLE
                val eng = MdocNfcEngagement.parseHandoverSelect(handover.handoverSelect) ?: run { status = "❌ Not an mdoc NFC tag"; return@launch }
                status = if (handover.negotiated) "Connecting over BLE (negotiated)…" else "Connecting over BLE…"
                val uuids = if (eng.peripheralServerMode) Ble.PERIPHERAL_SERVER else Ble.CENTRAL_CLIENT
                val transport = BleGattClientTransport(context, Ble.bytesToUuid(eng.serviceUuid), uuids, logger = LogWalletLogger()).also { it.connect() }
                status = "Requesting documents…"
                val docs = wallet.reader.read(transport, eng.deviceEngagement, readerRequest(), handoverNdef = handover.handoverSelect, handoverRequestNdef = handover.handoverRequest)
                results = docs
                status = if (docs.isEmpty()) "No documents returned" else "✅ Read ${docs.size} document(s)"
                LogStore.log("Reader read ${docs.size} document(s) over NFC+BLE")
            } catch (e: Throwable) {
                status = "❌ ${e.message}"
                LogStore.log("❌ Reader (NFC): ${e.message}")
            } finally {
                nfcWaiting = false
            }
        }
    }
    fun cancelNfc() { nfcJob?.cancel(); nfcWaiting = false; status = "Ready to read." }

    if (nfcWaiting) {
        Column(
            Modifier.fillMaxWidth().padding(20.dp, 24.dp, 20.dp, 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            NfcPulse()
            Text(status, style = MaterialTheme.typography.titleSmall, color = c.ink)
            SecondaryButton("Cancel", onClick = { cancelNfc() })
        }
        return
    }

    Column(
        Modifier.fillMaxWidth().padding(20.dp, 4.dp, 20.dp, 24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        WalletCard {
            Text("Verify a document in person", style = MaterialTheme.typography.titleSmall, color = c.ink)
            Spacer(Modifier.height(6.dp))
            Text(
                "This device acts as an ISO 18013-5 reader — scan the holder's QR (or tap over NFC), then read and verify their mdoc over Bluetooth.",
                style = MaterialTheme.typography.bodyMedium, color = c.inkMuted,
            )
        }
        PrimaryButton("Scan holder's QR", onClick = {
            ensureReady {
                AppLock.suppressResumeLock() // returning from the scanner shouldn't demand a re-unlock
                scanLauncher.launch(ScanOptions().apply {
                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    setPrompt("Scan the wallet's proximity QR")
                    setBeepEnabled(false)
                    setOrientationLocked(false)
                    setCaptureActivity(PortraitCaptureActivity::class.java)
                })
            }
        })
        SecondaryButton("Tap over NFC", onClick = { ensureReady { onNfc() } })

        if (status.isNotBlank()) {
            val tint = when { status.startsWith("❌") -> c.danger; status.startsWith("✅") -> c.trust; else -> c.inkMuted }
            Text(status.removePrefix("❌ ").removePrefix("✅ "), style = MaterialTheme.typography.bodyMedium, color = tint)
        }

        if (results.isNotEmpty()) {
            SectionLabel("Documents read")
            results.forEach { doc -> ReaderResultCard(doc) }
        }
    }
}

@Composable
private fun ReaderResultCard(doc: VerifiedDocument) {
    val c = WalletTheme.colors
    WalletCard(padding = PaddingValues(0.dp)) {
        Row(Modifier.fillMaxWidth().padding(16.dp, 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(docTypeLabel(doc.docType), style = MaterialTheme.typography.titleSmall, color = c.ink, modifier = Modifier.weight(1f))
            TrustBadge(doc.deviceAuthenticated, trustedText = "Verified", untrustedText = "Unverified")
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
        val flat = doc.elements.flatMap { (_, els) -> els.entries }
        if (flat.isEmpty()) InfoRow("Elements", "—")
        else flat.forEach { (k, v) -> InfoRow(claimPathLabel(listOf(k)), cborText(v)) }
    }
}

// ---------- helpers ----------

private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

private fun decodeEngagement(content: String): ByteArray? {
    if (!content.startsWith("mdoc:")) return null
    return runCatching { Base64.decode(content.removePrefix("mdoc:").trim(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) }.getOrNull()
}

private fun encodeQr(content: String): Bitmap = BarcodeEncoder().encodeBitmap(content, BarcodeFormat.QR_CODE, 600, 600)

private fun cborText(c: Cbor): String = when (c) {
    is Cbor.Text -> c.value
    is Cbor.UInt -> c.value.toString()
    is Cbor.NInt -> "-${c.n + 1uL}"
    is Cbor.Bool -> c.value.toString()
    is Cbor.Bytes -> "0x…(${c.value.size}B)"
    is Cbor.Tagged -> cborText(c.value)
    is Cbor.Array -> c.items.joinToString(", ") { cborText(it) }
    else -> c.toString()
}
