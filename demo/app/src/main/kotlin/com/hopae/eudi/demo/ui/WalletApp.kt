package com.hopae.eudi.demo.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.ReceiptLong
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Surface
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hopae.eudi.demo.DemoWallet
import com.hopae.eudi.demo.IncomingLink
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.PendingAuth
import com.hopae.eudi.demo.PortraitCaptureActivity
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.CredentialOffer
import com.hopae.eudi.wallet.IssuanceRequest
import com.hopae.eudi.wallet.IssuanceSession
import com.hopae.eudi.wallet.IssuanceState
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.PresentationRequest
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationSession
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import java.text.SimpleDateFormat
import java.time.Instant
import java.util.Date
import java.util.Locale

private class PendingConsent(val session: PresentationSession, val request: PresentationRequest)

@Composable
fun WalletApp(wallet: Wallet) {
    var tab by remember { mutableStateOf(0) }
    var refreshKey by remember { mutableStateOf(0) }
    var offerToConfirm by remember { mutableStateOf<CredentialOffer?>(null) }
    var txCodeFor by remember { mutableStateOf<CredentialOffer?>(null) }
    var consent by remember { mutableStateOf<PendingConsent?>(null) }
    var busy by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val openAuth: (String, IssuanceSession) -> Unit = { url, session ->
        PendingAuth.session = session
        LogStore.log("Opening browser for authorization…")
        runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.onFailure { LogStore.log("❌ open browser: ${it.message}") }
    }

    fun handleUri(uri: String, source: String) {
        val scheme = uri.substringBefore("://", "").lowercase()
        LogStore.log("$source [$scheme]: ${uri.take(140)}${if (uri.length > 140) "…" else ""}")
        when (scheme) {
            in OFFER_SCHEMES -> scope.launch {
                busy = "Resolving offer…"
                runCatching {
                    val offer = wallet.issuance.resolveOffer(uri)
                    LogStore.log("Offer: issuer=${offer.credentialIssuer}, configs=${offer.credentialConfigurationIds}, txCode=${offer.requiresTxCode}")
                    offerToConfirm = offer   // show the offer confirmation dialog before issuing
                }.onFailure { LogStore.log("❌ resolveOffer: ${it.message}") }
                busy = null
            }
            in VP_SCHEMES -> scope.launch {
                busy = "Resolving request…"
                runCatching {
                    val session = wallet.presentation.start(uri)
                    when (val r = session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }) {
                        is PresentationState.RequestResolved -> {
                            LogStore.log("Verifier: ${r.request.verifier.commonName ?: r.request.verifier.clientId} · trusted=${r.request.verifier.trusted} · satisfiable=${r.request.satisfiable}")
                            consent = PendingConsent(session, r.request)
                        }
                        is PresentationState.Failed -> LogStore.log("❌ ${r.error.message}")
                        else -> {}
                    }
                }.onFailure { LogStore.log("❌ presentation: ${it.message}") }
                busy = null
            }
            else -> LogStore.log("⚠️ Unrecognized scheme '$scheme' (expected an offer or presentation link)")
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val uri = result.contents
        if (uri == null) LogStore.log("Scan cancelled") else handleUri(uri, "Scanned")
    }

    val incoming by IncomingLink.flow.collectAsState()
    LaunchedEffect(incoming) {
        val uri = incoming ?: return@LaunchedEffect
        IncomingLink.consume()
        handleUri(uri, "Opened link")
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(selected = tab == 0, onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.CreditCard, null) }, label = { Text("Credentials") })
                NavigationBarItem(selected = tab == 1, onClick = { tab = 1; refreshKey++ },
                    icon = { Icon(Icons.Filled.ReceiptLong, null) }, label = { Text("Transactions") })
                NavigationBarItem(selected = tab == 2, onClick = { tab = 2 },
                    icon = { Icon(Icons.Filled.BugReport, null) }, label = { Text("Debug Log") })
            }
        },
        floatingActionButton = {
            if (tab == 0) {
                ExtendedFloatingActionButton(
                    onClick = {
                        scanLauncher.launch(ScanOptions().apply {
                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            setPrompt("Scan a credential offer or verifier request")
                            setBeepEnabled(false)
                            setOrientationLocked(false)
                            setCaptureActivity(PortraitCaptureActivity::class.java)
                        })
                    },
                    icon = { Icon(Icons.Filled.QrCodeScanner, null) },
                    text = { Text("Scan QR") },
                )
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                0 -> CredentialsScreen(wallet, refreshKey)
                1 -> TransactionsScreen(wallet, refreshKey)
                else -> DebugLogScreen()
            }
        }
    }

    offerToConfirm?.let { offer ->
        OfferConfirmDialog(
            offer = offer,
            onConfirm = {
                offerToConfirm = null
                if (offer.requiresTxCode) txCodeFor = offer
                else scope.launch { busy = "Issuing…"; runIssuance(wallet, offer, null, openAuth); refreshKey++; busy = null }
            },
            onCancel = { offerToConfirm = null; LogStore.log("Issuance cancelled") },
        )
    }

    txCodeFor?.let { offer ->
        TxCodeDialog(
            onSubmit = { code ->
                txCodeFor = null
                scope.launch { busy = "Issuing…"; runIssuance(wallet, offer, code, openAuth); refreshKey++; busy = null }
            },
            onDismiss = { txCodeFor = null; LogStore.log("Issuance cancelled (no tx_code)") },
        )
    }

    consent?.let { p ->
        ConsentDialog(
            request = p.request,
            onApprove = {
                consent = null
                scope.launch {
                    busy = "Presenting…"
                    try {
                        LogStore.log("Presenting (auto-select)…")
                        p.session.respond(PresentationSelection.auto(p.request))
                        val t = p.session.state.first { it.isTerminal }
                        LogStore.log(
                            when (t) {
                                is PresentationState.Completed -> "✅ Presented" + (t.redirectUri?.let { " → $it" } ?: "")
                                is PresentationState.Failed -> "❌ ${t.error.message}"
                                else -> t::class.simpleName ?: ""
                            },
                        )
                        refreshKey++
                    } finally {
                        busy = null
                    }
                }
            },
            onDecline = { consent = null; scope.launch { p.session.decline(); LogStore.log("Declined presentation") } },
        )
    }

    busy?.let { message ->
        Box(
            Modifier.fillMaxSize()
                .background(Color.Black.copy(alpha = 0.35f))
                .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {},
            contentAlignment = Alignment.Center,
        ) {
            Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 6.dp) {
                Row(Modifier.padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(28.dp), strokeWidth = 3.dp)
                    Spacer(Modifier.width(16.dp))
                    Text(message, style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
    }
}

private suspend fun runIssuance(
    wallet: Wallet,
    offer: CredentialOffer,
    txCode: String?,
    openAuth: (String, IssuanceSession) -> Unit,
) {
    val configId = offer.credentialConfigurationIds.first()
    LogStore.log("Issuance: start (config=$configId)")
    runCatching {
        val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, configId, txCode = txCode))
        session.state.first { s ->
            LogStore.log("  issuance → ${s::class.simpleName}")
            when (s) {
                is IssuanceState.TxCodeRequired -> txCode?.let { session.submitTxCode(it) }
                is IssuanceState.AuthorizationRequired -> openAuth(s.authorizationUrl, session)
                is IssuanceState.Completed -> LogStore.log("✅ Issued ${s.result.issued.size} credential(s)")
                is IssuanceState.Failed -> LogStore.log("❌ ${s.error.message}")
                else -> {}
            }
            s.isTerminal
        }
    }.onFailure { LogStore.log("❌ Issuance: ${it.message}") }
}

// Invocation schemes match the EUDI reference wallet — deep links route by scheme only (authoritative).
private val OFFER_SCHEMES = setOf("openid-credential-offer", "haip-vci")
private val VP_SCHEMES = setOf("openid4vp", "eudi-openid4vp", "mdoc-openid4vp", "haip-vp")

@Composable
private fun CredentialsScreen(wallet: Wallet, refreshKey: Int) {
    var creds by remember { mutableStateOf<List<Credential>>(emptyList()) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    suspend fun reload() {
        runCatching { wallet.credentials.list() }
            .onSuccess { creds = it; LogStore.log("Credentials list → ${it.size}") }
            .onFailure { LogStore.log("❌ credentials.list: ${it.javaClass.simpleName}: ${it.message}") }
    }
    LaunchedEffect(refreshKey) {
        reload()
        runCatching { wallet.credentials.changes.collect { reload() } }  // live-update on add/remove
    }
    var detail by remember { mutableStateOf<Credential?>(null) }
    Column(Modifier.padding(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Credentials (${creds.size})", style = MaterialTheme.typography.titleLarge)
            TextButton(onClick = { scope.launch { reload() } }) { Text("Refresh") }
        }
        Spacer(Modifier.height(8.dp))
        if (creds.isEmpty()) Text("No credentials yet — tap Scan QR to issue one.", style = MaterialTheme.typography.bodyMedium)
        else Text("Tap a card for details.", style = MaterialTheme.typography.bodySmall)
        LazyColumn {
            items(creds) { c -> CredentialCard(c) { detail = c } }
        }
    }

    detail?.let { c ->
        CredentialDetailDialog(
            c = c,
            onCopy = {
                scope.launch {
                    val raw = runCatching { wallet.credentials.export(c.id) }.getOrNull()
                    if (raw.isNullOrEmpty()) {
                        LogStore.log("❌ export: nothing to copy for ${c.id.value}")
                    } else {
                        clipboard.setText(AnnotatedString(raw))
                        LogStore.log("Copied raw credential ${c.id.value} (${raw.length} chars)")
                    }
                }
            },
            onDelete = {
                detail = null
                scope.launch {
                    runCatching { wallet.credentials.delete(c.id) }
                        .onSuccess { LogStore.log("Deleted credential ${c.id.value}") }
                        .onFailure { LogStore.log("❌ delete: ${it.message}") }
                    reload()
                }
            },
            onDismiss = { detail = null },
        )
    }
}

@Composable
private fun CredentialCard(c: Credential, onClick: () -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 6.dp).clickable { onClick() }) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(credentialTitle(c), style = MaterialTheme.typography.titleMedium)
                c.issuer?.displayName?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text("Issued ${issuedDate(c)}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            FormatChip(c.format)
        }
    }
}

@Composable
private fun CredentialDetailDialog(c: Credential, onCopy: () -> Unit, onDelete: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(credentialTitle(c)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                DetailRow("Type", formatLabel(c.format))
                c.issuer?.displayName?.let { DetailRow("Issuer", it) }
                c.issuer?.url?.let { DetailRow("Issuer URL", it) }
                DetailRow("Issued", issuedDate(c))
                (c.lifecycle as? Lifecycle.Issued)?.let { lc ->
                    lc.validity?.validUntil?.let { DetailRow("Expires", instantDate(it)) }
                    if (lc.claims.isNotEmpty()) {
                        Spacer(Modifier.height(12.dp))
                        Text("CLAIMS", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                        if (c.format is CredentialFormat.MsoMdoc) {
                            val ns = lc.claims.mapNotNull { it.path.firstOrNull() }.distinct().joinToString(", ")
                            if (ns.isNotEmpty()) Text(ns, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Spacer(Modifier.height(4.dp))
                        lc.claims.forEach { DetailRow(claimLabel(c, it.path), it.value.display()) }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        dismissButton = {
            Row {
                TextButton(onClick = onCopy) { Text("Copy") }
                TextButton(onClick = onDelete) { Text("Delete", color = Color(0xFFC62828)) }
            }
        },
    )
}

@Composable
private fun DetailRow(name: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(name, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(12.dp))
        Text(value, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1.3f))
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
}

private fun credentialTitle(c: Credential): String = when (val f = c.format) {
    is CredentialFormat.SdJwtVc -> f.vct
    is CredentialFormat.MsoMdoc -> f.docType
}

/** mdoc claim paths start with the namespace (same for every element) — drop it for readability. */
private fun claimLabel(c: Credential, path: List<String>): String {
    val p = if (c.format is CredentialFormat.MsoMdoc && path.size > 1) path.drop(1) else path
    return p.joinToString(" › ")
}

private fun formatLabel(format: CredentialFormat): String = when (format) {
    is CredentialFormat.SdJwtVc -> "SD-JWT VC"
    is CredentialFormat.MsoMdoc -> "mdoc"
}

private val cardDateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
private fun issuedDate(c: Credential): String = cardDateFmt.format(Date.from(c.createdAt))
private fun instantDate(i: Instant): String = cardDateFmt.format(Date.from(i))

@Composable
private fun FormatChip(format: CredentialFormat) {
    Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = MaterialTheme.shapes.small) {
        Text(
            formatLabel(format),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

@Composable
private fun InfoBox(title: String, content: @Composable ColumnScope.() -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp)) {
            Text(title.uppercase(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(6.dp))
            content()
        }
    }
}

@Composable
private fun TrustBadge(trusted: Boolean) {
    val bg = if (trusted) Color(0xFF2E7D32) else Color(0xFFC62828)
    Surface(color = bg, shape = MaterialTheme.shapes.small) {
        Text(
            if (trusted) "✓ Verified" else "⚠ Not verified",
            color = Color.White,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}


@Composable
private fun TransactionsScreen(wallet: Wallet, refreshKey: Int) {
    var entries by remember { mutableStateOf<List<TransactionLogEntry>>(emptyList()) }
    val scope = rememberCoroutineScope()
    suspend fun reload() { entries = wallet.transactions.history() }
    LaunchedEffect(refreshKey) { reload() }
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US) }
    Column(Modifier.padding(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Transaction Log (${entries.size})", style = MaterialTheme.typography.titleLarge)
            TextButton(onClick = { scope.launch { DemoWallet.transactionStore.clear(); reload() } }) { Text("Clear") }
        }
        Spacer(Modifier.height(8.dp))
        if (entries.isEmpty()) Text("No presentations recorded yet.", style = MaterialTheme.typography.bodyMedium)
        LazyColumn {
            items(entries) { e ->
                Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("${e.type} · ${e.status}", style = MaterialTheme.typography.titleMedium)
                        Text(fmt.format(Date(e.timestamp * 1000)), style = MaterialTheme.typography.bodySmall)
                        e.relyingParty?.let { rp ->
                            Text("→ ${rp.name ?: rp.id}  ${if (rp.trusted) "✅ trusted" else "⚠️ untrusted"}", style = MaterialTheme.typography.bodySmall)
                        }
                        e.documents.forEach { d ->
                            Text("${d.type ?: d.format}: ${d.claims.joinToString(", ") { it.path.joinToString(".") }}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DebugLogScreen() {
    val lines by LogStore.lines.collectAsState()
    val clipboard = LocalClipboardManager.current
    Column(Modifier.padding(16.dp).fillMaxSize()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Debug Log (${lines.size})", style = MaterialTheme.typography.titleLarge)
            Row {
                TextButton(onClick = { clipboard.setText(AnnotatedString(LogStore.asText())) }) { Text("Copy") }
                TextButton(onClick = { LogStore.clear() }) { Text("Clear") }
            }
        }
        Spacer(Modifier.height(8.dp))
        SelectionContainer {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                lines.forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
            }
        }
    }
}

@Composable
private fun OfferConfirmDialog(offer: CredentialOffer, onConfirm: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Receive credential?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                InfoBox("Issuer") {
                    Text(hostOf(offer.credentialIssuer), style = MaterialTheme.typography.titleMedium)
                    Text(offer.credentialIssuer, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                InfoBox(if (offer.credentialConfigurationIds.size > 1) "Credentials" else "Credential") {
                    offer.credentialConfigurationIds.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
                    if (offer.requiresTxCode) {
                        Spacer(Modifier.height(6.dp))
                        Text("Requires a transaction code (PIN)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        },
        confirmButton = { Button(onClick = onConfirm) { Text("OK") } },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

private fun hostOf(url: String): String = runCatching { java.net.URI(url).host ?: url }.getOrDefault(url)

@Composable
private fun TxCodeDialog(onSubmit: (String) -> Unit, onDismiss: () -> Unit) {
    var code by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Transaction code") },
        text = {
            OutlinedTextField(code, { code = it }, label = { Text("tx_code") }, singleLine = true)
        },
        confirmButton = { TextButton(onClick = { onSubmit(code) }, enabled = code.isNotBlank()) { Text("Issue") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ConsentDialog(request: PresentationRequest, onApprove: () -> Unit, onDecline: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text("Present to verifier?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                InfoBox("Verifier") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(request.verifier.commonName ?: request.verifier.clientId, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        Spacer(Modifier.width(8.dp))
                        TrustBadge(request.verifier.trusted)
                    }
                    if (request.verifier.commonName != null) {
                        Text(request.verifier.clientId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                InfoBox("Will share") {
                    request.queries.forEach { q ->
                        val cand = q.candidates.firstOrNull()
                        if (cand == null) {
                            Text("${q.queryId}: no matching credential", style = MaterialTheme.typography.bodySmall, color = Color(0xFFC62828))
                        } else {
                            Text("${q.queryId}${if (q.required) "" else " (optional)"}", style = MaterialTheme.typography.labelMedium)
                            cand.disclosedPaths.forEach { Text("• ${it.joinToString(" › ")}", style = MaterialTheme.typography.bodyMedium) }
                        }
                    }
                    if (!request.satisfiable) {
                        Spacer(Modifier.height(4.dp))
                        Text("No matching credential.", style = MaterialTheme.typography.bodySmall, color = Color(0xFFC62828))
                    }
                }
            }
        },
        confirmButton = { Button(onClick = onApprove, enabled = request.satisfiable) { Text("Present") } },
        dismissButton = { TextButton(onClick = onDecline) { Text("Decline") } },
    )
}
