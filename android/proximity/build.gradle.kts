plugins {
    id("com.android.library")
}

group = "com.hopae.eudi.android"
version = "0.0.1-SNAPSHOT"

android {
    namespace = "com.hopae.eudi.wallet.android.proximity"
    compileSdk = 36

    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // ProximityTransport / NfcCarrier ports + the SDK proximity module (DeviceEngagement, Ident helpers).
    api("com.hopae.eudi:wallet-api:0.0.1-SNAPSHOT")
    api("com.hopae.eudi:proximity:0.0.1-SNAPSHOT")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
