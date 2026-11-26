pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories {
        google(); mavenCentral()
        maven("https://chaquo.com/maven")   // Chaquopy：在 Android 上内嵌 Python 3
    }
}
rootProject.name = "CTFKit"
include(":app")
// 复用 TesseraUI 的 Android 组件库（Git 子模块）
include(":tessera")
project(":tessera").projectDir = file("../../vendor/TesseraUI/platforms/android/tessera")
