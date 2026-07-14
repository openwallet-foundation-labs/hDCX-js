package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.ui.components.absorbTouches
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.Pill
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustBadge
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.theme.DocGradients
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.CredentialOffer
import com.hopae.eudi.wallet.OfferPreview
import com.hopae.eudi.wallet.IssuanceRequest
import com.hopae.eudi.wallet.IssuanceSession
import com.hopae.eudi.wallet.IssuanceState
import com.hopae.eudi.wallet.Wallet
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.net.URI

private enum class IssueStep { Review, TxCode, Issuing, Success, Failed }

@Composable
fun IssueScreen(
    offer: CredentialOffer,
    wallet: Wallet,
    onAuth: (String, IssuanceSession) -> Unit,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = WalletTheme.colors
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf(IssueStep.Review) }
    var txCode by remember { mutableStateOf("") }
    var issued by remember { mutableStateOf<Credential?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val configId = offer.credentialConfigurationIds.firstOrNull() ?: ""

    fun runIssuance(code: String?) {
        step = IssueStep.Issuing
        scope.launch {
            runCatching {
                val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, configId, txCode = code))
                val terminal = session.state.first { s ->
                    when (s) {
                        is IssuanceState.TxCodeRequired -> code?.let { session.submitTxCode(it) }
                        is IssuanceState.AuthorizationRequired -> onAuth(s.authorizationUrl, session)
                        else -> {}
                    }
                    s.isTerminal
                }
                when (terminal) {
                    is IssuanceState.Completed -> {
                        LogStore.log("✅ Issued ${terminal.result.issued.size} credential(s)")
                        issued = wallet.credentials.list().maxByOrNull { it.createdAt }
                        step = IssueStep.Success
                    }
                    is IssuanceState.Deferred -> { issued = null; step = IssueStep.Success }
                    is IssuanceState.Failed -> { error = terminal.error.message; step = IssueStep.Failed }
                    else -> { error = "Unexpected state"; step = IssueStep.Failed }
                }
            }.onFailure { error = it.message; step = IssueStep.Failed; LogStore.log("❌ Issuance: ${it.message}") }
        }
    }

    val topInset = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    val bottomInset = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()

    Column(
        Modifier.fillMaxSize().background(c.screen).absorbTouches()
            .padding(start = 20.dp, end = 20.dp, top = topInset + 12.dp, bottom = bottomInset + 20.dp),
    ) {
        // header (hidden on the terminal screens which have their own centered layout)
        if (step == IssueStep.Review || step == IssueStep.TxCode) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(36.dp).clip(RoundedCornerShape(99.dp)).background(c.card)
                        .clickable { if (step == IssueStep.TxCode) step = IssueStep.Review else onCancel() },
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = c.ink, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(10.dp))
                Text("Add document", style = MaterialTheme.typography.titleMedium, color = c.ink)
            }
            Spacer(Modifier.height(20.dp))
        }

        when (step) {
            IssueStep.Review -> ReviewStep(offer, wallet, onContinue = {
                if (offer.requiresTxCode) step = IssueStep.TxCode else runIssuance(null)
            }, onCancel = onCancel)
            IssueStep.TxCode -> TxCodeStep(txCode, onChange = { txCode = it }, onSubmit = { runIssuance(txCode) })
            IssueStep.Issuing -> CenteredStatus { Loading("Issuing…", "Contacting the issuer and verifying the credential.") }
            IssueStep.Success -> CenteredStatus { SuccessStep(issued, onDone) }
            IssueStep.Failed -> CenteredStatus { FailedStep(error, onCancel) }
        }
    }
}

@Composable
private fun ReviewStep(offer: CredentialOffer, wallet: Wallet, onContinue: () -> Unit, onCancel: () -> Unit) {
    val c = WalletTheme.colors
    var preview by remember { mutableStateOf<OfferPreview?>(null) }
    var loading by remember { mutableStateOf(true) }
    LaunchedEffect(offer) {
        preview = runCatching { wallet.issuance.previewOffer(offer) }.getOrNull()
        loading = false
    }
    val configId = offer.credentialConfigurationIds.firstOrNull() ?: ""
    val primary = preview?.credentials?.firstOrNull()
    val title = primary?.displayName ?: prettyConfig(configId)
    val host = hostOf(offer.credentialIssuer)

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        // The credential being added.
        Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Brush.linearGradient(DocGradients.Pid)).padding(20.dp)) {
            Column {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("NEW DOCUMENT", style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.85f), modifier = Modifier.weight(1f))
                    primary?.format?.takeIf { it.isNotBlank() }?.let { Pill(formatLabel(it), Color.White.copy(alpha = 0.12f), Color.White) }
                }
                Spacer(Modifier.height(22.dp))
                Text(title, style = MaterialTheme.typography.titleMedium, color = Color.White)
                Spacer(Modifier.height(3.dp))
                Text(host, style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.75f))
            }
        }

        // Who's issuing it, and whether they're a registered issuer (trusted list) — resolved live.
        SectionLabel("Issuer")
        WalletCard {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f)) {
                    Text(preview?.issuerDisplayName ?: host, style = MaterialTheme.typography.titleSmall, color = c.ink)
                    Text(host, style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
                }
                if (loading) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = c.brand)
                else TrustBadge(preview?.issuerRegistered == true, trustedText = "Registered", untrustedText = "Unverified")
            }
        }
        preview?.takeIf { !it.issuerRegistered && !loading }?.let {
            Text(
                "This issuer isn't on the EU trusted list. You can still add the document.",
                style = MaterialTheme.typography.bodySmall, color = c.inkMuted,
            )
        }

        // More than one credential offered → list them.
        preview?.credentials?.takeIf { it.size > 1 }?.let { creds ->
            SectionLabel("You'll receive")
            WalletCard(padding = PaddingValues(0.dp)) {
                creds.forEach { InfoRow(it.displayName ?: prettyConfig(it.configurationId), formatLabel(it.format)) }
            }
        }
        if (offer.requiresTxCode) {
            Text("This issuer will ask for a transaction code.", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
        }

        Spacer(Modifier.height(4.dp))
        PrimaryButton("Continue", onContinue)
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text("Cancel", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, modifier = Modifier.clickable { onCancel() }.padding(10.dp))
        }
    }
}

private fun formatLabel(format: String): String = when {
    format.contains("sd-jwt", true) || format.contains("sd_jwt", true) -> "SD-JWT VC"
    format.contains("mdoc", true) || format.contains("mso", true) -> "mdoc"
    format.isBlank() -> "Credential"
    else -> format
}

@Composable
private fun TxCodeStep(code: String, onChange: (String) -> Unit, onSubmit: () -> Unit) {
    val c = WalletTheme.colors
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Enter the transaction code", style = MaterialTheme.typography.titleSmall, color = c.ink)
        Text("The issuer sent you a code to authorise this credential.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
        OutlinedTextField(code, onChange, label = { Text("Transaction code") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.weight(1f))
        PrimaryButton("Issue", onSubmit, enabled = code.isNotBlank())
    }
}

@Composable
private fun ColumnScope.CenteredStatus(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        content = content,
    )
}

@Composable
private fun Loading(title: String, subtitle: String) {
    val c = WalletTheme.colors
    CircularProgressIndicator(color = c.brand)
    Spacer(Modifier.height(20.dp))
    Text(title, style = MaterialTheme.typography.titleMedium, color = c.ink)
    Spacer(Modifier.height(8.dp))
    Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
}

@Composable
private fun SuccessStep(issued: Credential?, onDone: () -> Unit) {
    val c = WalletTheme.colors
    Box(Modifier.size(84.dp).clip(RoundedCornerShape(99.dp)).background(c.trustBg), contentAlignment = Alignment.Center) {
        Icon(Icons.Filled.Check, null, tint = c.trust, modifier = Modifier.size(40.dp))
    }
    Spacer(Modifier.height(20.dp))
    Text("Document added", style = MaterialTheme.typography.titleLarge, color = c.ink)
    Spacer(Modifier.height(8.dp))
    Text("Stored securely on this device.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
    issued?.issuer?.let { info ->
        Spacer(Modifier.height(20.dp))
        WalletCard(padding = PaddingValues(0.dp)) {
            TrustRow("Credential signature", trustLabel(info.trusted), info.trusted == true)
            Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
            TrustRow("Issuer registration", trustLabel(info.registered), info.registered == true)
        }
    }
    Spacer(Modifier.height(28.dp))
    PrimaryButton("View in wallet", onDone)
}

@Composable
private fun FailedStep(error: String?, onClose: () -> Unit) {
    val c = WalletTheme.colors
    Box(Modifier.size(84.dp).clip(RoundedCornerShape(99.dp)).background(c.dangerBg), contentAlignment = Alignment.Center) {
        Text("!", style = MaterialTheme.typography.titleLarge, color = c.danger)
    }
    Spacer(Modifier.height(20.dp))
    Text("Couldn't add document", style = MaterialTheme.typography.titleMedium, color = c.ink)
    Spacer(Modifier.height(8.dp))
    Text(error ?: "The issuance failed.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
    Spacer(Modifier.height(28.dp))
    PrimaryButton("Close", onClose)
}

private fun trustLabel(flag: Boolean?): String = when (flag) { true -> "Trusted"; false -> "Not verified"; null -> "Not checked" }
private fun hostOf(url: String): String = runCatching { URI(url).host ?: url }.getOrDefault(url)
private fun prettyConfig(id: String): String =
    id.substringAfterLast('/').substringAfterLast(':').replace('_', ' ').replace('.', ' ').trim().replaceFirstChar { it.uppercase() }.ifBlank { "Credential" }
private fun glyphOf(id: String): String {
    val t = id.lowercase()
    return when { "pid" in t -> "ID"; "mdl" in t || "mdoc" in t -> "DL"; "health" in t || "ehic" in t -> "HC"; else -> "DC" }
}
