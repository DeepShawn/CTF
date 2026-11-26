package com.ctfkit.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import com.ctfkit.app.ui.HomeScreen
import com.ctfkit.app.ui.ToolScreen
import com.tesseraui.TesseraTheme
import com.tesseraui.Tessera
import com.tesseraui.foundation.TesseraShape
import com.tesseraui.components.TesseraSpinner
import com.tesseraui.TesseraText

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) Python.start(AndroidPlatform(this))
        enableEdgeToEdge()
        setContent { App() }
    }
}

@Composable
fun App() {
    // 外观设置（简化版：跟随系统深浅色，三种形状可切换）
    var shape by remember { mutableStateOf(TesseraShape.Tile) }
    TesseraTheme(shape = shape) {
        // 简单的两级导航：工具列表 ↔ 工具详情
        var current by remember { mutableStateOf<String?>(null) }
        // 首次加载 manifest（读取一次，在后台）
        var ready by remember { mutableStateOf(false) }
        LaunchedEffect(Unit) {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { Ctfkit.categories }
            ready = true
        }
        if (!ready) {
            Box(Modifier.fillMaxSize(), contentAlignment = androidx.compose.ui.Alignment.Center) {
                Column(horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    TesseraSpinner()
                    TesseraText("正在启动 Python…", style = Tessera.type.bodySm, color = Tessera.colors.textSecondary)
                }
            }
            return@TesseraTheme
        }
        val toolId = current
        if (toolId == null) {
            HomeScreen(onOpen = { current = it }, shape = shape, onShape = { shape = it })
        } else {
            ToolScreen(toolId = toolId, onBack = { current = null })
        }
    }
}
