package com.ctfkit.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.ctfkit.app.Ctfkit
import com.ctfkit.app.Field
import com.ctfkit.app.Tool
import com.tesseraui.Tessera
import com.tesseraui.TesseraText
import com.tesseraui.components.*
import com.tesseraui.icons.TesseraIcons
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

@Composable
fun ToolScreen(toolId: String, onBack: () -> Unit) {
    val t = Ctfkit.byId[toolId] ?: return
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    // 参数状态：字段 id -> 值
    val values = remember(toolId) {
        mutableStateMapOf<String, Any?>().apply {
            (t.inputs + t.options).forEach { f -> put(f.id, f.default ?: defaultFor(f)) }
        }
    }
    var output by remember(toolId) { mutableStateOf<JSONObject?>(null) }
    var running by remember(toolId) { mutableStateOf(false) }
    var showSource by remember(toolId) { mutableStateOf(false) }
    var sourceText by remember(toolId) { mutableStateOf<String?>(null) }

    fun run() {
        running = true
        scope.launch {
            val params = JSONObject().apply { values.forEach { (k, v) -> put(k, v) } }
            val r = withContext(Dispatchers.IO) { Ctfkit.run(toolId, params) }
            output = r
            running = false
        }
    }

    // live 工具：参数变化后自动运行（简单防抖）
    LaunchedEffect(toolId) {
        if (t.live && t.examples.isEmpty()) run()
    }

    Column(Modifier.fillMaxSize().padding(WindowInsets.safeDrawing.asPaddingValues())) {
        // 顶栏
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically) {
            TesseraIconButton(icon = TesseraIcons.ArrowLeft, onClick = onBack, contentDescription = "返回")
            TesseraText(t.title, style = Tessera.type.title3, modifier = Modifier.weight(1f).padding(start = 4.dp))
        }
        Column(Modifier.fillMaxSize().weight(1f).verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (t.chapter.isNotEmpty()) TesseraTag("教材 " + t.chapter, tone = TesseraTone.Accent)
                TesseraTag("离线可用", tone = TesseraTone.Success, icon = TesseraIcons.Check)
            }
            TesseraText(t.summary, style = Tessera.type.bodySm, color = Tessera.colors.textSecondary)

            // 参数表单
            TesseraCard {
                val visible = visibleFields(t, values)
                for (f in visible) {
                    FieldEditor(f, values[f.id]) { values[f.id] = it; if (t.live) run() }
                    Spacer(Modifier.height(10.dp))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    TesseraButton(if (t.live) "运行" else "运行", onClick = { run() }, icon = TesseraIcons.Play,
                        loading = running)
                    if (t.examples.isNotEmpty()) {
                        TesseraButton("填入示例", onClick = {
                            val ex = t.examples.first()
                            (t.inputs + t.options).forEach { f -> values[f.id] = ex[f.id] ?: f.default ?: defaultFor(f) }
                            run()
                        }, variant = com.tesseraui.components.TesseraButtonVariant.Secondary)
                    }
                }
            }

            // 结果
            TesseraCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TesseraText("结果", style = Tessera.type.title3, modifier = Modifier.weight(1f))
                    val out = output
                    if (out != null && out.optBoolean("ok")) {
                        TesseraButton("复制", onClick = {
                            clipboard.setText(AnnotatedString(outputToText(out.getJSONObject("output"))))
                        }, size = com.tesseraui.components.TesseraButtonSize.Sm,
                            variant = com.tesseraui.components.TesseraButtonVariant.Secondary, icon = TesseraIcons.Copy)
                    }
                }
                Spacer(Modifier.height(10.dp))
                OutputView(output, running)
            }

            // 讲解
            TesseraCard {
                TesseraText("讲解", style = Tessera.type.title3)
                Spacer(Modifier.height(8.dp))
                TesseraSegmentedControl(
                    options = listOf("原理", "Python 代码"),
                    selectedIndex = if (showSource) 1 else 0,
                    onSelect = { idx ->
                        showSource = idx == 1
                        if (idx == 1 && sourceText == null) {
                            scope.launch { sourceText = withContext(Dispatchers.IO) { Ctfkit.source(toolId) } }
                        }
                    }, small = true,
                )
                Spacer(Modifier.height(10.dp))
                if (!showSource) {
                    MarkdownText(t.principle)
                } else {
                    val s = sourceText
                    if (s == null) TesseraSkeleton(Modifier.fillMaxWidth().height(200.dp))
                    else CodeBlock(s)
                }
            }
            Spacer(Modifier.height(40.dp))
        }
    }
}

private fun defaultFor(f: Field): Any? = when (f.type) {
    "number" -> 0
    "switch" -> false
    "segmented", "select" -> f.choices.firstOrNull() ?: ""
    else -> ""
}

private fun visibleFields(t: Tool, values: Map<String, Any?>): List<Field> =
    (t.inputs + t.options).filter { f ->
        f.visibleWhen.all { (k, allowed) -> allowed.contains(values[k]?.toString()) }
    }

@Composable
private fun FieldEditor(f: Field, value: Any?, onChange: (Any?) -> Unit) {
    when (f.type) {
        "text" -> TesseraTextArea(value?.toString() ?: "", onChange, label = f.label,
            placeholder = f.placeholder.ifEmpty { null }, help = f.help.ifEmpty { null }, minLines = 3)
        "string" -> TesseraTextField(value?.toString() ?: "", onChange, label = f.label,
            placeholder = f.placeholder.ifEmpty { null }, help = f.help.ifEmpty { null })
        "number" -> TesseraNumberInput((value?.toString()?.toDoubleOrNull()) ?: 0.0,
            { onChange(it.toInt()) }, label = f.label,
            min = (f.min ?: Int.MIN_VALUE).toDouble(), max = (f.max ?: Int.MAX_VALUE).toDouble())
        "select" -> TesseraSelect(f.choices, f.choices.indexOf(value?.toString()).coerceAtLeast(0),
            { onChange(f.choices[it]) }, label = f.label)
        "segmented" -> Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (f.label.isNotEmpty()) TesseraText(f.label, style = Tessera.type.label)
            TesseraSegmentedControl(f.choices, f.choices.indexOf(value?.toString()).coerceAtLeast(0),
                { onChange(f.choices[it]) })
            if (f.help.isNotEmpty()) TesseraText(f.help, style = Tessera.type.caption, color = Tessera.colors.textTertiary)
        }
        "switch" -> TesseraSwitch(value == true || value == "true", { onChange(it) }, label = f.label)
        "file" -> TesseraText("（此工具需要上传文件，请使用网页版或电脑端）", style = Tessera.type.bodySm,
            color = Tessera.colors.textTertiary)
    }
}

@Composable
private fun OutputView(output: JSONObject?, running: Boolean) {
    if (running && output == null) {
        TesseraProgress(value = null, modifier = Modifier.fillMaxWidth())
        return
    }
    if (output == null) {
        TesseraText("填好参数后运行", style = Tessera.type.bodySm, color = Tessera.colors.textTertiary)
        return
    }
    if (!output.optBoolean("ok")) {
        TesseraBanner(text = output.optString("error", "出错了"), tone = TesseraTone.Danger)
        return
    }
    RenderOutput(output.getJSONObject("output"))
}

@Composable
private fun RenderOutput(o: JSONObject) {
    when (o.getString("type")) {
        "text" -> CodeBlock(o.getString("value"))
        "code" -> CodeBlock(o.getString("value"))
        "fields" -> {
            val items = o.getJSONArray("items")
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                for (i in 0 until items.length()) {
                    val pair = items.getJSONArray(i)
                    Column {
                        TesseraText(pair.get(0).toString(), style = Tessera.type.caption, color = Tessera.colors.textSecondary)
                        TesseraText(pair.get(1).toString(), style = Tessera.type.bodySm)
                    }
                }
            }
        }
        "table" -> {
            val cols = o.getJSONArray("columns")
            val rows = o.getJSONArray("rows")
            Column(Modifier.horizontalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    for (i in 0 until cols.length())
                        TesseraText(cols.getString(i), style = Tessera.type.caption, color = Tessera.colors.textSecondary,
                            modifier = Modifier.widthIn(min = 60.dp))
                }
                for (r in 0 until minOf(rows.length(), 200)) {
                    val row = rows.getJSONArray(r)
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        for (i in 0 until row.length())
                            TesseraText(row.get(i).toString(), style = Tessera.type.bodySm, modifier = Modifier.widthIn(min = 60.dp))
                    }
                }
            }
            TesseraText("共 ${rows.length()} 行", style = Tessera.type.caption, color = Tessera.colors.textTertiary)
        }
        "group" -> {
            val items = o.getJSONArray("items")
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                for (i in 0 until items.length()) RenderOutput(items.getJSONObject(i))
            }
        }
        "image" -> TesseraText("（图片结果，请在网页版查看）", style = Tessera.type.bodySm, color = Tessera.colors.textTertiary)
        "file" -> TesseraText("（文件结果 ${o.optString("name")}，${o.optInt("size")} 字节，请在网页版下载）",
            style = Tessera.type.bodySm, color = Tessera.colors.textTertiary)
    }
}

@Composable
private fun CodeBlock(text: String) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp))
            .background(Tessera.colors.fillDefault)
            .padding(12.dp).horizontalScroll(rememberScrollState())
    ) {
        TesseraText(text, style = Tessera.type.bodySm.copy(fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace))
    }
}

@Composable
private fun MarkdownText(md: String) {
    // 极简渲染：去掉表格竖线，保留段落；手机上原理文字以纯文本显示即可
    val clean = md.replace(Regex("\\*\\*([^*]+)\\*\\*"), "$1").replace("`", "")
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for (para in clean.split("\n\n")) {
            if (para.isBlank()) continue
            TesseraText(para.trim().replace("\n", " "), style = Tessera.type.bodySm)
        }
    }
}

private fun outputToText(o: JSONObject): String = when (o.getString("type")) {
    "text", "code" -> o.getString("value")
    "fields" -> {
        val items = o.getJSONArray("items")
        (0 until items.length()).joinToString("\n") {
            val p = items.getJSONArray(it); "${p.get(0)}: ${p.get(1)}"
        }
    }
    "table" -> {
        val cols = o.getJSONArray("columns"); val rows = o.getJSONArray("rows")
        val header = (0 until cols.length()).joinToString("\t") { cols.getString(it) }
        val body = (0 until rows.length()).joinToString("\n") { r ->
            val row = rows.getJSONArray(r); (0 until row.length()).joinToString("\t") { row.get(it).toString() }
        }
        "$header\n$body"
    }
    "group" -> {
        val items = o.getJSONArray("items")
        (0 until items.length()).joinToString("\n\n") { outputToText(items.getJSONObject(it)) }
    }
    else -> ""
}