package com.payeshgpt.security

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : Activity() {
    private lateinit var output: TextView
    private lateinit var summary: TextView
    private val nativeBridge by lazy { NativeBridge() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 32, 24, 24)
            setBackgroundColor(0xFF101820.toInt())
        }
        val title = TextView(this).apply {
            text = "پایش‌GPT | آزمایشگاه امنیت اندروید"
            textSize = 22f
            setTextColor(0xFFFFFFFF.toInt())
            gravity = Gravity.CENTER
        }
        summary = TextView(this).apply {
            textSize = 14f
            setTextColor(0xFFB7D8E8.toInt())
            setPadding(0, 18, 0, 18)
            text = "وضعیت: آمادهٔ بررسی محدود و فقط‌خواندنی"
        }
        val inventory = Button(this).apply {
            text = "فهرست برنامه‌های قابل‌اجرا"
            setOnClickListener { showApps() }
        }
        val assess = Button(this).apply {
            text = "ساخت گزارش شواهد با هستهٔ Rust"
            setOnClickListener { buildReport() }
        }
        output = TextView(this).apply {
            textSize = 13f
            setTextColor(0xFFE5EDF2.toInt())
            setPadding(0, 16, 0, 24)
            text = "این نسخه هنوز اسکنر بدافزار یا آشکارساز روت‌کیت نیست."
        }
        root.addView(title, matchWrap())
        root.addView(summary, matchWrap())
        root.addView(inventory, matchWrap())
        root.addView(assess, matchWrap())
        val scroll = ScrollView(this).apply { addView(output) }
        root.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
        ))
        setContentView(root)
    }

    private fun matchWrap() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    )

    @Suppress("DEPRECATION")
    private fun showApps() {
        try {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val apps = packageManager.queryIntentActivities(intent, 0)
                .mapNotNull { it.activityInfo?.applicationInfo }
                .distinctBy { it.packageName }
                .sortedBy { packageManager.getApplicationLabel(it).toString().lowercase() }
            output.text = buildString {
                append("برنامه‌های قابل‌اجرا: ${apps.size}\n")
                append("محدودیت: این فهرست الزاماً همهٔ بسته‌های نصب‌شده را شامل نمی‌شود.\n\n")
                apps.forEach { app ->
                    append("• ")
                    append(packageManager.getApplicationLabel(app))
                    append("\n  ")
                    append(app.packageName)
                    append("\n")
                }
            }
            summary.text = "فهرست محدود برنامه‌ها آماده شد؛ این نتیجه حکم پاک‌بودن دستگاه نیست."
        } catch (e: Exception) {
            output.text = "خواندن فهرست برنامه‌ها ناموفق بود: ${e.javaClass.simpleName}"
            summary.text = "بررسی کامل نشد"
        }
    }

    private fun buildReport() {
        try {
            // Empty evidence must remain inconclusive; never manufacture a clean result.
            val report = JSONObject(nativeBridge.assessJson(JSONArray().toString()))
            output.text = report.toString(2)
            summary.text = "گزارش هستهٔ Rust ساخته شد؛ شواهدی برای نتیجه‌گیری امنیتی جمع‌آوری نشده است."
        } catch (e: UnsatisfiedLinkError) {
            output.text = "کتابخانهٔ بومی در APK موجود نیست یا برای این معماری ساخته نشده است."
            summary.text = "اتصال هستهٔ بومی در دسترس نیست"
        } catch (e: Exception) {
            output.text = "ساخت گزارش ناموفق بود: ${e.javaClass.simpleName}"
            summary.text = "گزارش کامل نشد"
        }
    }
}
