import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

plugins {
    id("com.android.application")
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        load(file.inputStream())
    }
}

val rawTunnelId = System.getenv("CUSTOM_TUNNEL_ID")?.takeIf { it.isNotBlank() }
    ?: localProperties.getProperty("TUNNEL_ID")?.takeIf { it.isNotBlank() }
    ?: throw GradleException("Build failed: TUNNEL_ID is not specified!")

val tunnelId = rawTunnelId.toIntOrNull()
    ?: throw GradleException("Build failed: TUNNEL_ID must be a valid integer.")

println("--> [Gradle Build Config] Successfully resolved TUNNEL_ID: $tunnelId")

android {
    namespace = "com.dev.fido.bridge"
    // Compile against API 37 required by OkHttp 5.5.1 AAR metadata while preserving Android 14+ (API 34) runtime floor
    compileSdk = 37

    // Enforce deterministic APK signing certificate so external credential providers
    // (e.g., Authnkey, Bitwarden) can reliably verify the app's SHA-256 fingerprint allowlist.
    signingConfigs {
        create("fixedConfig") {
            val keystoreFile = rootProject.file("my-release-key.jks")
            if (keystoreFile.exists()) {
                storeFile = keystoreFile
                // Prioritize environment variables (CI), fallback to local.properties (local dev)
                storePassword = System.getenv("STORE_PASSWORD") ?: localProperties.getProperty("STORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS") ?: localProperties.getProperty("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD") ?: localProperties.getProperty("KEY_PASSWORD")
            } else if (System.getenv("CI") == "true" || System.getenv("GITHUB_ACTIONS") == "true") {
                // Fail fast in CI environments to prevent producing unsigned or mismatched APKs
                // that silently break CredentialManager privileged allowlist checks.
                throw GradleException("Build failed: my-release-key.jks is missing in CI environment!")
            }
        }
    }

    defaultConfig {
        applicationId = "com.dev.fido.bridge"
        minSdk = 34
        targetSdk = 35
        versionCode = 7
        versionName = "1.3.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("int", "TUNNEL_ID", "$tunnelId")
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("fixedConfig")
        }
        release {
            signingConfig = signingConfigs.getByName("fixedConfig")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        // Disable viewBinding as UI is constructed programmatically, reducing build overhead
        buildConfig = true
    }
}

// Configure Kotlin bytecode target using the modern compilerOptions DSL
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.appcompat:appcompat:1.7.1")

    // Android 14+ CredentialManager (Core API)
    // Omit legacy credentials-play-services-auth dependency to prevent unwanted GMS permissions
    implementation("androidx.credentials:credentials:1.3.0")

    // Coroutines & WebSockets
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // Use OkHttp 5.x for native RFC 8305 Happy Eyeballs (fastFallback) dual-stack route racing
    // while retaining the eMudhra intermediate CA blocklist on AOSP devices
    implementation("com.squareup.okhttp3:okhttp:5.5.1")

    // Matrix-only QR code generator for CTAP 2.3 client hybrid flow
    implementation("com.google.zxing:core:3.5.4")
}