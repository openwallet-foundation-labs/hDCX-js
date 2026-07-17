import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release (upload) signing — read from demo/keystore.properties (gitignored); absent on machines that only
// build debug. See wallet-provider/PLAY-INTEGRITY.md for why a Play-signed release build is needed.
val keystoreProps = rootProject.file("keystore.properties").takeIf { it.exists() }?.let {
    Properties().apply { load(FileInputStream(it)) }
}

android {
    namespace = "com.hopae.eudi.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.hopae.axle.wallet"
        minSdk = 29
        targetSdk = 36
        versionCode = 7
        versionName = "0.7"
    }

    buildFeatures { compose = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        if (keystoreProps != null) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        getByName("debug") { isMinifyEnabled = false }
        getByName("release") {
            isMinifyEnabled = false // wallet uses reflection (CBOR/JOSE); keep R8 off for this test build
            if (keystoreProps != null) signingConfig = signingConfigs.getByName("release")
        }
    }
}

dependencies {
    // EUDI Wallet SDK (via composite build ../kotlin)
    implementation("com.hopae.eudi:wallet:0.0.1-SNAPSHOT")
    implementation("com.hopae.eudi:wallet-api:0.0.1-SNAPSHOT")
    // Trusted-list client: pulls the issuer + registrar CA anchors from the JAdES trusted lists into TrustConfig.
    implementation("com.hopae.eudi:trustlist:0.0.1-SNAPSHOT")
    // Android platform adapters — via composite build ../android (distinct group to avoid clashing with the SDK)
    implementation("com.hopae.eudi.android:core:0.0.1-SNAPSHOT")
    implementation("com.hopae.eudi.android:proximity:0.0.1-SNAPSHOT")
    implementation("com.hopae.eudi.android:dcapi:0.0.1-SNAPSHOT")
    // Wallet Provider backend client: client-auth WUA + per-issuance key attestation (HAIP §4.4.1 / §4.5.1).
    implementation("com.hopae.eudi.android:attestation:0.0.1-SNAPSHOT")
    // debug-grade software SecureArea + in-memory helpers
    implementation("com.hopae.eudi:testkit:0.0.1-SNAPSHOT")

    // Jetpack Compose
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")

    // App lock: biometric + PIN. BiometricPrompt requires a FragmentActivity host.
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.biometric:biometric:1.1.0")
    // PIN secret at rest (EncryptedSharedPreferences)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // QR scanning (camera)
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Digital Credentials API (Credential Manager provider) — custom OpenID4VP-1.0 matcher via GMS
    implementation("androidx.credentials:credentials:1.6.0-rc01")
    implementation("com.google.android.gms:play-services-identity-credentials:16.0.0-alpha08")
}
