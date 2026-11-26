package com.ctfkit.app

import com.chaquo.python.Python
import org.json.JSONArray
import org.json.JSONObject

/** 工具描述（来自 ctfkit 的 manifest）。 */
data class Field(
    val id: String, val type: String, val label: String,
    val default: Any?, val choices: List<String>, val help: String, val placeholder: String,
    val min: Int?, val max: Int?, val visibleWhen: Map<String, List<String>>,
)

data class Tool(
    val id: String, val title: String, val category: String, val chapter: String,
    val summary: String, val principle: String, val module: String, val live: Boolean,
    val inputs: List<Field>, val options: List<Field>, val examples: List<Map<String, Any?>>,
)

data class Category(val key: String, val title: String, val chapter: String)

/** 封装对 Python（Chaquopy）的调用。manifest 只读一次。 */
object Ctfkit {
    private val bridge by lazy { Python.getInstance().getModule("bridge") }

    val categories: List<Category> by lazy { loadCategories() }
    val tools: List<Tool> by lazy { loadTools() }
    val byId: Map<String, Tool> by lazy { tools.associateBy { it.id } }
    private val manifestJson: JSONObject by lazy { JSONObject(bridge.callAttr("manifest").toString()) }

    val version: String get() = manifestJson.optString("version", "0.1.0")

    private fun loadCategories(): List<Category> {
        val cats = manifestJson.getJSONObject("categories")
        return cats.keys().asSequence().map { k ->
            val o = cats.getJSONObject(k)
            Category(k, o.getString("title"), o.optString("chapter", ""))
        }.toList()
    }

    private fun field(o: JSONObject): Field {
        val choices = o.optJSONArray("choices")?.let { a -> List(a.length()) { a.getString(it) } } ?: emptyList()
        val vw = mutableMapOf<String, List<String>>()
        o.optJSONObject("visibleWhen")?.let { w ->
            w.keys().forEach { k ->
                val v = w.get(k)
                vw[k] = if (v is JSONArray) List(v.length()) { v.getString(it) } else listOf(v.toString())
            }
        }
        return Field(
            o.getString("id"), o.getString("type"), o.optString("label", ""),
            if (o.has("default")) o.get("default") else null, choices,
            o.optString("help", ""), o.optString("placeholder", ""),
            if (o.has("min")) o.getInt("min") else null, if (o.has("max")) o.getInt("max") else null, vw,
        )
    }

    private fun loadTools(): List<Tool> {
        val arr = manifestJson.getJSONArray("tools")
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            fun fields(name: String) = o.getJSONArray(name).let { a -> List(a.length()) { field(a.getJSONObject(it)) } }
            val examples = o.getJSONArray("examples").let { a ->
                List(a.length()) { idx ->
                    val e = a.getJSONObject(idx)
                    e.keys().asSequence().associateWith { e.get(it) }
                }
            }
            Tool(
                o.getString("id"), o.getString("title"), o.getString("category"), o.optString("chapter", ""),
                o.optString("summary", ""), o.optString("principle", ""), o.optString("module", ""),
                o.optBoolean("live", true), fields("inputs"), fields("options"), examples,
            )
        }
    }

    /** 运行工具，返回 JSON 字符串（与 Web 端一致）。应在后台线程调用。 */
    fun run(toolId: String, params: JSONObject): JSONObject =
        JSONObject(bridge.callAttr("run", toolId, params.toString()).toString())

    fun source(toolId: String): String = bridge.callAttr("source", toolId).toString()
}
