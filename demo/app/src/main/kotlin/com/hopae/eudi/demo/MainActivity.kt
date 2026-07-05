package com.hopae.eudi.demo

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import com.hopae.eudi.demo.ui.WalletApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wallet = DemoWallet.get(this)
        handleAuthRedirect(intent)
        setContent {
            MaterialTheme {
                Surface { WalletApp(wallet) }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAuthRedirect(intent)
    }

    /** Resume an issuance session waiting on the authorization-code browser redirect. */
    private fun handleAuthRedirect(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "eu.europa.ec.euidi") PendingAuth.complete(data.toString())
    }
}
