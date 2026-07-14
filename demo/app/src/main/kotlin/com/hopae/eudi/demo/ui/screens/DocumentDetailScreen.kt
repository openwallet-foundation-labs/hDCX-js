package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.credFormatLabel
import com.hopae.eudi.demo.ui.credIsMdl
import com.hopae.eudi.demo.ui.credKicker
import com.hopae.eudi.demo.ui.credTitle
import com.hopae.eudi.demo.ui.components.absorbTouches
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.Pill
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Claim
import com.hopae.eudi.wallet.ClaimCategory
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.spi.CredentialFormat

@Composable
fun DocumentDetailScreen(
    cred: Credential,
    onBack: () -> Unit,
    onPresentProximity: (() -> Unit)?,
    onDelete: () -> Unit,
) {
    val c = WalletTheme.colors
    var reveal by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }
    val claims = (cred.lifecycle as? Lifecycle.Issued)?.claims.orEmpty()
    val topInset = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    val bottomInset = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()

    Column(
        Modifier.fillMaxSize().background(c.screen).absorbTouches().verticalScroll(rememberScrollState())
            .padding(start = 20.dp, end = 20.dp, top = topInset + 12.dp, bottom = bottomInset + 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // top bar
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircleIcon(Icons.AutoMirrored.Filled.ArrowBack, onBack)
            Spacer(Modifier.width(10.dp))
            Text(credTitle(cred), style = MaterialTheme.typography.titleMedium, color = c.ink, modifier = Modifier.weight(1f))
            if (claims.any { isSensitive(it.path) }) {
                CircleIcon(if (reveal) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility) { reveal = !reveal }
                Spacer(Modifier.width(8.dp))
            }
            Box {
                CircleIcon(Icons.Filled.MoreVert) { menuOpen = true }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text("Delete document", color = c.danger, style = MaterialTheme.typography.bodyMedium) },
                        leadingIcon = { Icon(Icons.Outlined.Delete, null, tint = c.danger, modifier = Modifier.size(18.dp)) },
                        onClick = { menuOpen = false; confirmDelete = true },
                    )
                }
            }
        }

        // gradient card
        Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Brush.linearGradient(com.hopae.eudi.demo.ui.credGradient(cred))).padding(20.dp)) {
            Column {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(credKicker(cred).uppercase(), style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.85f), modifier = Modifier.weight(1f))
                    Pill(credFormatLabel(cred), Color.White.copy(alpha = 0.12f), Color.White)
                }
                Spacer(Modifier.height(22.dp))
                Text(credTitle(cred), style = MaterialTheme.typography.titleMedium, color = Color.White)
                cred.issuer?.displayName?.let {
                    Spacer(Modifier.height(3.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.75f))
                }
            }
        }

        // trust panel (2A registration + 2B credential signature)
        SectionLabel("Trust")
        WalletCard(padding = PaddingValues(0.dp)) {
            TrustRow("Credential signature", trustText(cred.issuer?.trusted), cred.issuer?.trusted == true)
            Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
            TrustRow("Issuer registration", trustText(cred.issuer?.registered), cred.issuer?.registered == true)
        }

        // Claims vs. credential metadata — classified by the SDK (SD-JWT registered claims + ARF/ISO admin fields).
        val personal = claims.filter { it.category != ClaimCategory.Metadata }
        val metadata = claims.filter { it.category == ClaimCategory.Metadata }
        if (personal.isNotEmpty()) {
            SectionLabel("Claims")
            ClaimsCard(cred, personal, reveal)
        }
        if (metadata.isNotEmpty()) {
            SectionLabel("Metadata")
            ClaimsCard(cred, metadata, reveal)
        }

        // Proximity is the one genuinely holder-initiated present action (show *this* mDL over BLE/NFC).
        // Cross-device / QR presentation is request-driven — it starts by scanning the verifier from Home.
        // (Delete lives in the top-right overflow menu.)
        onPresentProximity?.let {
            Spacer(Modifier.height(4.dp))
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(c.brand)
                    .clickable { it() }.padding(vertical = 15.dp),
                horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.Sensors, null, tint = Color.White, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(9.dp))
                Text("Present via proximity", style = MaterialTheme.typography.labelLarge, color = Color.White)
            }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete ${credTitle(cred)}?") },
            text = { Text("This removes the credential from this device. You can be issued a new one later.") },
            confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Delete", color = c.danger) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun CircleIcon(icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    val c = WalletTheme.colors
    Box(
        Modifier.size(36.dp).clip(RoundedCornerShape(99.dp)).background(c.card).clickable { onClick() },
        contentAlignment = Alignment.Center,
    ) { Icon(icon, null, tint = c.ink, modifier = Modifier.size(18.dp)) }
}

@Composable
private fun ClaimsCard(cred: Credential, items: List<Claim>, reveal: Boolean) {
    WalletCard(padding = PaddingValues(0.dp)) {
        items.forEach { claim ->
            val raw = claim.value.display() // SDK-typed rendering (arrays → list, booleans → Yes/No)
            val value = if (isSensitive(claim.path) && !reveal) mask(raw) else raw
            InfoRow(claimLabel(cred, claim.path), value)
        }
    }
}

private fun trustText(flag: Boolean?): String = when (flag) {
    true -> "Trusted"
    false -> "Not verified"
    null -> "Not checked"
}

/** mdoc claim paths start with the namespace (same for every element) — drop it for readability. */
private fun claimLabel(cred: Credential, path: List<String>): String {
    val p = if (cred.format is CredentialFormat.MsoMdoc && path.size > 1) path.drop(1) else path
    return p.joinToString(" › ") { it.replace('_', ' ').replaceFirstChar { ch -> ch.uppercase() } }
}

private val SENSITIVE = listOf("number", "identifier", "birth", "national", "iban", "administrative", "document", "passport", "ssn", "tax")
private fun isSensitive(path: List<String>): Boolean {
    val key = path.lastOrNull()?.lowercase() ?: return false
    return SENSITIVE.any { it in key }
}

private fun mask(v: String): String = v.map { if (it.isLetterOrDigit()) '•' else it }.joinToString("")
