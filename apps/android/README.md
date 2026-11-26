# CTFKit · Android

Android 版，使用 [Jetpack Compose](https://developer.android.com/jetpack/compose) + [TesseraUI](https://github.com/DeepShawn/TesseraUI) 界面，
通过 [Chaquopy](https://chaquo.com/chaquopy/) 在应用内嵌 **Python 3.12**，运行与 Web、Docker 完全相同的 `ctfkit` 包。

- 最低 Android 7.0（API 24），与 TesseraUI 一致；
- 工具页由 `ctfkit manifest` 的工具描述文件自动生成，新增工具不用改 Android 代码；
- v0.1 的工具只用 Python 标准库，离线可用，不联网。

## 构建

需要 Android SDK（platform 35、build-tools 35）、JDK 17。TesseraUI 以 Git 子模块方式引入，先确保已拉取：

```bash
git submodule update --init
cd apps/android
# local.properties 里写 sdk.dir=<Android SDK 路径>，或设置 ANDROID_HOME
gradle :app:assembleDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`（约 45 MB，含两套 ABI 的 Python 运行时）。
正式发布时按 `arm64-v8a`、`x86_64` 分包可减小体积。

## 结构

| 文件 | 说明 |
|---|---|
| `app/src/main/python/bridge.py` | Kotlin 与 Python 之间的桥，JSON 进出，与 Web 端 `worker.js` 一致 |
| `app/src/main/kotlin/.../Ctfkit.kt` | 读取 manifest、调用工具的封装 |
| `app/src/main/kotlin/.../ui/HomeScreen.kt` | 工具列表（按章节分类、搜索） |
| `app/src/main/kotlin/.../ui/ToolScreen.kt` | 工具页：由描述文件生成表单、运行、显示结果与讲解 |
| `app/build.gradle.kts` | `chaquopy { sourceSets { srcDir("../../../core") } }` 把仓库根部的 `ctfkit` 打包进来 |

算法只写一份（`core/ctfkit`），Android、Web、Docker 共用；新增工具后三端自动获得。

## 已知限制（v0.1）

- 需要上传文件的工具（取证、隐写）在手机端暂未接入系统文件选择，工具页会提示改用网页版；后续版本补齐。
- 图片 / 文件类输出在手机端只提示，不显示预览；后续版本接入 TesseraUI 的 ImageViewer。
