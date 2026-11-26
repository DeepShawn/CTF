package com.ctfkit.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.ctfkit.app.Ctfkit
import com.ctfkit.app.Tool
import com.tesseraui.Tessera
import com.tesseraui.TesseraText
import com.tesseraui.foundation.TesseraShape
import com.tesseraui.components.*

@Composable
fun HomeScreen(onOpen: (String) -> Unit, shape: TesseraShape, onShape: (TesseraShape) -> Unit) {
    var query by remember { mutableStateOf("") }
    val tools = Ctfkit.tools
    val filtered = remember(query) {
        if (query.isBlank()) tools
        else tools.filter { t ->
            val hay = (t.id + t.title + t.summary + t.chapter + t.keywordsText()).lowercase()
            query.lowercase().split(" ").all { it.isBlank() || hay.contains(it) }
        }
    }
    val grouped = remember(filtered) { filtered.groupBy { it.category } }

    Column(Modifier.fillMaxSize().padding(WindowInsets.safeDrawing.asPaddingValues())) {
        Column(Modifier.padding(horizontal = 20.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TesseraText("CTF 工具包", style = Tessera.type.title1, modifier = Modifier.weight(1f))
                TesseraText("v" + Ctfkit.version, style = Tessera.type.caption, color = Tessera.colors.textTertiary)
            }
            TesseraSegmentedControl(
                options = listOf("拼贴", "圆融", "流韵"),
                selectedIndex = when (shape) { TesseraShape.Tile -> 0; TesseraShape.Round -> 1; else -> 2 },
                onSelect = { onShape(when (it) { 0 -> TesseraShape.Tile; 1 -> TesseraShape.Round; else -> TesseraShape.Flow }) },
                small = true,
            )
            TesseraSearchField(query = query, onQueryChange = { query = it }, onSearch = {}, placeholder = "搜索 ${tools.size} 个工具")
        }
        LazyColumn(
            Modifier.fillMaxSize().weight(1f),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (query.isBlank()) {
                item {
                    TesseraBanner(
                        text = "本工具包仅用于学习、CTF 比赛与已获授权的安全测试。未经授权对他人系统进行扫描、入侵或破坏违反相关法律法规。",
                        title = "使用声明",
                        tone = TesseraTone.Warning,
                    )
                }
            }
            for (cat in Ctfkit.categories) {
                val list = grouped[cat.key] ?: continue
                item(key = "h-" + cat.key) {
                    Row(Modifier.padding(top = 10.dp), verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TesseraText(cat.title, style = Tessera.type.title3)
                        TesseraBadge(list.size, color = Tessera.colors.accentSolid)
                        if (cat.chapter.isNotEmpty())
                            TesseraText("教材 " + cat.chapter, style = Tessera.type.caption, color = Tessera.colors.textTertiary)
                    }
                }
                items(list, key = { it.id }) { t -> ToolCard(t, onOpen) }
            }
            item { Spacer(Modifier.height(40.dp)) }
        }
    }
}

@Composable
private fun ToolCard(t: Tool, onOpen: (String) -> Unit) {
    TesseraCard(onClick = { onOpen(t.id) }, padding = 16.dp) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TesseraText(t.title, style = Tessera.type.title3, modifier = Modifier.weight(1f))
            if (t.chapter.isNotEmpty()) TesseraTag(t.chapter)
        }
        Spacer(Modifier.height(6.dp))
        TesseraText(t.summary, style = Tessera.type.bodySm, color = Tessera.colors.textSecondary)
    }
}

private fun Tool.keywordsText(): String = ""   // manifest 中的 keywords 已并入搜索的其他字段
