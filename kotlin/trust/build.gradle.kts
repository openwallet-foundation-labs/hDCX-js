plugins {
    kotlin("jvm")
    `java-test-fixtures`
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    api(project(":openid4vci"))
    api(project(":openid4vp"))
    api(project(":sdjwt"))
    api(project(":mdoc"))
    testImplementation(kotlin("test"))
    // generate certificate hierarchies with SAN for deterministic chain-validation tests (shared via testFixtures)
    testFixturesImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
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
