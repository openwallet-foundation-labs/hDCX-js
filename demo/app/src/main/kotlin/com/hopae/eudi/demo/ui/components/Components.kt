package com.hopae.eudi.demo.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.runtime.remember
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hopae.eudi.demo.ui.theme.SectionLabelStyle
import com.hopae.eudi.demo.ui.theme.WalletTheme

/**
 * Swallows taps on empty areas so a full-screen overlay (issue / document / transaction detail) doesn't leak
 * touches through to the bottom navigation bar rendered behind it. Children with their own click handlers are
 * hit-tested first, so buttons still work.
 */
@Composable
fun Modifier.absorbTouches(): Modifier =
    this.clickable(interactionSource = remember { MutableInteractionSource() }, indication = null, onClick = {})

/** Uppercase, letter-spaced section header used throughout the design (e.g. "DATA TO BE REQUESTED"). */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(text.uppercase(), style = SectionLabelStyle, color = WalletTheme.colors.inkFaint, modifier = modifier)
}

/** The standard white, rounded, hairline-bordered card the whole UI is built from. */
@Composable
fun WalletCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    padding: PaddingValues = PaddingValues(16.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    val c = WalletTheme.colors
    val shape = RoundedCornerShape(16.dp)
    var m = modifier.fillMaxWidth().clip(shape).background(c.card).border(BorderStroke(1.dp, c.cardBorder), shape)
    if (onClick != null) m = m.clickable { onClick() }
    Column(m.padding(padding), content = content)
}

/** Primary call-to-action button — brand blue. */
@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val c = WalletTheme.colors
    val bg = if (enabled) c.brand else c.cardBorderStrong
    Box(
        modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(bg)
            .then(if (enabled) Modifier.clickable { onClick() } else Modifier)
            .padding(vertical = 15.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = Color.White, style = MaterialTheme.typography.labelLarge)
    }
}

/** Secondary button — white with a hairline border. */
@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, tint: Color? = null) {
    val c = WalletTheme.colors
    Box(
        modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(c.card)
            .border(BorderStroke(1.dp, c.cardBorderStrong), RoundedCornerShape(14.dp))
            .clickable { onClick() }.padding(vertical = 14.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = tint ?: c.ink, style = MaterialTheme.typography.labelLarge)
    }
}

/** A rounded pill/chip. */
@Composable
fun Pill(text: String, bg: Color, fg: Color, border: Color? = null, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(99.dp)
    var m = modifier.clip(shape).background(bg)
    if (border != null) m = m.border(BorderStroke(1.dp, border), shape)
    Text(
        text,
        color = fg,
        style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.sp),
        modifier = m.padding(horizontal = 11.dp, vertical = 5.dp),
    )
}

/** The green "Wallet secured" status pill from Home. */
@Composable
fun SecuredPill() {
    val c = WalletTheme.colors
    Row(
        Modifier.clip(RoundedCornerShape(99.dp)).background(c.trustBg)
            .border(BorderStroke(1.dp, c.trustBorder), RoundedCornerShape(99.dp))
            .padding(horizontal = 11.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(Modifier.size(7.dp).clip(RoundedCornerShape(99.dp)).background(c.trust))
        Text("Wallet secured", color = c.trust, style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.sp))
    }
}

/** A trust/verification badge: green when trusted, amber-red when not. */
@Composable
fun TrustBadge(trusted: Boolean, trustedText: String = "Verified", untrustedText: String = "Not verified") {
    val c = WalletTheme.colors
    if (trusted) Pill("✓ $trustedText", c.trustBg, c.trustDeep, c.trustBorder)
    else Pill("⚠ $untrustedText", c.dangerBg, c.danger, c.dangerBorder)
}

/** A gradient document tile with a short glyph (e.g. "ID", "DL"). */
@Composable
fun DocTile(glyph: String, colors: List<Color>, size: Int = 42) {
    Box(
        Modifier.size(size.dp).clip(RoundedCornerShape((size / 3.5f).dp)).background(Brush.linearGradient(colors)),
        contentAlignment = Alignment.Center,
    ) {
        Text(glyph, color = Color.White, style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight(800)))
    }
}

/** A shield-check row used in the trust-check panels. */
@Composable
fun TrustRow(label: String, value: String, ok: Boolean = true) {
    val c = WalletTheme.colors
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(Icons.Filled.VerifiedUser, null, tint = if (ok) c.trust else c.inkFaint, modifier = Modifier.size(15.dp))
        Text(label, style = MaterialTheme.typography.bodyMedium, color = c.inkBody, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = if (ok) c.trust else c.inkMuted, fontWeight = FontWeight(700))
    }
}

/** A key/value row with a bottom hairline divider (document detail, review lists). */
@Composable
fun InfoRow(label: String, value: String, valueColor: Color? = null) {
    val c = WalletTheme.colors
    Column {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 13.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, modifier = Modifier.weight(1f))
            Spacer(Modifier.width(12.dp))
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                color = valueColor ?: c.ink,
                fontWeight = FontWeight(700),
                textAlign = TextAlign.End,
                modifier = Modifier.weight(1.4f),
                overflow = TextOverflow.Ellipsis,
            )
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
    }
}
