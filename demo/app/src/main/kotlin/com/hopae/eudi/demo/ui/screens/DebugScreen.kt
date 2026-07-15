package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.collectAsState
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.ui.theme.ConsoleBg
import com.hopae.eudi.demo.ui.theme.ConsoleBorder
import com.hopae.eudi.demo.ui.theme.ConsoleChipActive
import com.hopae.eudi.demo.ui.theme.ConsolePanel
import com.hopae.eudi.demo.ui.theme.ConsoleText
import com.hopae.eudi.demo.ui.theme.ConsoleTextDim
import com.hopae.eudi.demo.ui.theme.LogError
import com.hopae.eudi.demo.ui.theme.LogInfo
import com.hopae.eudi.demo.ui.theme.LogWarn
import com.hopae.eudi.demo.ui.theme.MonoStyle

private enum class Level { INFO, WARN, ERROR }

private fun levelOf(line: String): Level = when {
    "❌" in line || "ERROR" in line -> Level.ERROR
    "⚠" in line || "WARN" in line -> Level.WARN
    else -> Level.INFO
}

@Composable
fun DebugScreen(onBack: () -> Unit) {
    val lines by LogStore.lines.collectAsState()
    val clipboard = LocalClipboardManager.current
    var filter by remember { mutableStateOf<Level?>(null) }
    // Newest-first on screen (like the activity list); the store/export stay chronological.
    val shown = lines.filter { filter == null || levelOf(it) == filter }.asReversed()

    Column(Modifier.fillMaxSize().background(ConsoleBg)) {
        // top bar
        Row(
            Modifier.fillMaxWidth().padding(12.dp, 16.dp, 12.dp, 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                Modifier.size(34.dp).clip(RoundedCornerShape(99.dp)).background(ConsolePanel).clickable { onBack() },
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = ConsoleText, modifier = Modifier.size(18.dp)) }
            Text("Debug log", color = ConsoleText, style = MonoStyle.copy(fontSize = 14.sp), modifier = Modifier.weight(1f))
            ConsoleAction("Copy") { clipboard.setText(AnnotatedString(LogStore.asText())) }
            ConsoleAction("Clear") { LogStore.clear() }
        }
        // filter chips
        Row(Modifier.fillMaxWidth().padding(12.dp, 4.dp, 12.dp, 10.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Chip("ALL", filter == null) { filter = null }
            Chip("INFO", filter == Level.INFO) { filter = Level.INFO }
            Chip("WARN", filter == Level.WARN) { filter = Level.WARN }
            Chip("ERROR", filter == Level.ERROR) { filter = Level.ERROR }
        }
        LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp, 0.dp, 14.dp, 24.dp)) {
            items(shown) { line ->
                val col = when (levelOf(line)) { Level.ERROR -> LogError; Level.WARN -> LogWarn; Level.INFO -> ConsoleText }
                Text(line, color = col, style = MonoStyle, modifier = Modifier.padding(vertical = 2.dp))
            }
        }
    }
}

@Composable
private fun ConsoleAction(text: String, onClick: () -> Unit) {
    Text(
        text, color = LogInfo, style = MonoStyle,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(ConsolePanel).clickable { onClick() }.padding(10.dp, 6.dp),
    )
}

@Composable
private fun Chip(label: String, active: Boolean, onClick: () -> Unit) {
    Text(
        label,
        color = if (active) ConsoleText else ConsoleTextDim,
        style = MonoStyle,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(if (active) ConsoleChipActive else ConsolePanel)
            .border(1.dp, if (active) ConsoleBorder else ConsolePanel, RoundedCornerShape(8.dp))
            .clickable { onClick() }.padding(11.dp, 6.dp),
    )
}
