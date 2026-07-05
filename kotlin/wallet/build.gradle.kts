plugins {
    kotlin("jvm")
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // Public API exposes only wallet-api (ports + value types) + own types.
    api(project(":wallet-api"))
    // Protocol engines are internal wiring — hidden from the public API.
    implementation(project(":credential-store"))
    implementation(project(":sdjwt"))
    implementation(project(":mdoc"))
    implementation(project(":trust"))
    implementation(project(":statuslist"))
    implementation(project(":openid4vci"))
    implementation(project(":openid4vp"))
    implementation(project(":proximity"))

    testImplementation(kotlin("test"))
    testImplementation(project(":testkit"))
    testImplementation(testFixtures(project(":mdoc")))
    testImplementation(testFixtures(project(":openid4vci")))
    testImplementation(testFixtures(project(":openid4vp")))
    testImplementation(testFixtures(project(":trust")))
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}
