pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "eudi-wallet-android"

// The SDK modules (com.hopae.eudi:wallet-api, :txlog, …) are provided by the ../kotlin composite build,
// which the consuming build (the demo) includes alongside this one; its substitutions resolve them here.
include(":core")
include(":proximity")
