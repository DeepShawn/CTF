plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

android {
    namespace = "com.ctfkit.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.ctfkit.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }   // 真机 + 模拟器
    }
    buildFeatures { compose = true }
    kotlinOptions { jvmTarget = "17" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

// Chaquopy：在 Android 上内嵌 Python 3，运行与 Web、Docker 共用的 ctfkit 包
chaquopy {
    defaultConfig {
        version = "3.12"
        // v0.1 的工具只用标准库，不需要 pip 依赖
    }
    sourceSets {
        getByName("main") {
            srcDir("../../../core")        // 仓库根部 core/ 里的 ctfkit
            srcDir("src/main/python")      // 本应用的 bridge.py
        }
    }
}

dependencies {
    implementation(project(":tessera"))
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
