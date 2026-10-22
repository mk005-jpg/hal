package com.secpen.halinject

import android.app.Activity
import android.content.Intent
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.File

// Target apps — all 8 KYC targets (informational only; injection applies to
// whichever app is using the back camera at the time)
private val TARGETS = listOf(
    "com.deblock.deblockapp"        to "Deblock (FaceTec + Regula)",
    "tech.pnlfin.finom"             to "Finom (SumSub)",
    "com.moneybookers.skrillpayments" to "Skrill (Jumio)",
    "com.kaching.merchant"          to "Kaching (Onfido)",
    "com.bunq.android"              to "Bunq (Incode)",
    "vivid.money"                   to "Vivid (Veriff)",
    "com.transferwise.android"      to "Wise (FaceTec)",
    "eu.qonto.qonto"                to "Qonto (Fourthline/Onfido)"
)

private const val REQ_IMAGE = 1001

class MainActivity : AppCompatActivity() {

    private val bridge = DaemonBridge()
    private val handler = Handler(Looper.getMainLooper())

    // Views
    private lateinit var tvStatus:    TextView
    private lateinit var tvNode:      TextView
    private lateinit var ivPreview:   ImageView
    private lateinit var tvImagePath: TextView
    private lateinit var btnPick:     Button
    private lateinit var btnToggle:   Button
    private lateinit var llTargets:   LinearLayout
    private lateinit var tvStats:     TextView

    private var injecting = false
    private var imagePath: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        ensureDaemon()

        bridge.onStatus = { status ->
            handler.post {
                applyStatus(status)
            }
        }
        bridge.startPolling()
    }

    override fun onDestroy() {
        super.onDestroy()
        bridge.stopPolling()
    }

    // ── Activity result: image picked ─────────────────────────────────────────
    override fun onActivityResult(req: Int, result: Int, data: Intent?) {
        super.onActivityResult(req, result, data)
        if (req != REQ_IMAGE || result != Activity.RESULT_OK) return
        val uri: Uri = data?.data ?: return
        toast("Preparing image…")

        Thread {
            val path = ImagePrep.prepare(this, uri)
            handler.post {
                if (path != null) {
                    imagePath = path
                    tvImagePath.text = "Image: ${File(path).name}"
                    val bmp = BitmapFactory.decodeFile(path)
                    if (bmp != null) ivPreview.setImageBitmap(bmp)
                    bridge.setImage(path)
                    toast("Frame ready")
                } else {
                    toast("Image preparation failed")
                }
            }
        }.start()
    }

    // ── UI ────────────────────────────────────────────────────────────────────
    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            setBackgroundColor(Color.parseColor("#1a1a2e"))
        }
        setContentView(root)

        // Title
        root.addView(textView("HAL Inject — Pixel 7a", 22f, Color.WHITE, true))
        root.addView(textView("Back camera only · front cam untouched", 13f, Color.GRAY))
        root.addView(divider())

        // Status card
        tvStatus = textView("Daemon: checking…", 14f, Color.YELLOW)
        tvNode   = textView("Back cam node: detecting…", 12f, Color.LTGRAY)
        root.addView(card(tvStatus, tvNode))

        // Image section
        ivPreview   = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 220)
            scaleType = ImageView.ScaleType.CENTER_CROP
            setBackgroundColor(Color.parseColor("#2a2a3e"))
        }
        tvImagePath = textView("No image selected", 12f, Color.LTGRAY)
        btnPick     = button("Pick Injection Frame") { pickImage() }
        root.addView(card(ivPreview, tvImagePath, btnPick))

        // Target apps list
        llTargets = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        TARGETS.forEach { (pkg, label) ->
            llTargets.addView(targetRow(pkg, label))
        }
        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        scroll.addView(card(textView("Target Apps (informational)", 13f, Color.WHITE, true), llTargets))
        root.addView(scroll)

        // Stats
        tvStats = textView("Frames: —", 12f, Color.LTGRAY)
        root.addView(card(tvStats))

        // Toggle button
        btnToggle = button("START INJECTION", Color.parseColor("#00c853")) {
            toggleInjection()
        }
        root.addView(btnToggle)
    }

    private fun applyStatus(s: DaemonStatus) {
        if (!s.connected) {
            tvStatus.text = "Daemon: NOT CONNECTED"
            tvStatus.setTextColor(Color.RED)
            return
        }
        tvStatus.text = "Daemon: connected | Frida PID ${s.fridaPid}"
        tvStatus.setTextColor(if (s.active) Color.parseColor("#00c853") else Color.YELLOW)
        if (s.backNode.isNotEmpty()) tvNode.text = "Back cam: ${s.backNode}"
        if (s.active && !injecting) {
            injecting = true
            btnToggle.text = "STOP INJECTION"
            btnToggle.setBackgroundColor(Color.parseColor("#d32f2f"))
        } else if (!s.active && injecting) {
            injecting = false
            btnToggle.text = "START INJECTION"
            btnToggle.setBackgroundColor(Color.parseColor("#00c853"))
        }
        // Read stats file
        readStatsFile()
    }

    private fun readStatsFile() {
        Thread {
            try {
                val f = File("/data/local/tmp/hal_inject/stats.json")
                if (f.exists()) {
                    val json = org.json.JSONObject(f.readText())
                    val inj  = json.optInt("injected", 0)
                    val skip = json.optInt("skipped", 0)
                    val err  = json.optInt("errors", 0)
                    handler.post {
                        tvStats.text = "Injected: $inj  |  Skipped: $skip  |  Errors: $err"
                    }
                }
            } catch (_: Exception) {}
        }.start()
    }

    private fun toggleInjection() {
        if (imagePath == null) { toast("Pick an image first"); return }
        Thread {
            if (!injecting) {
                bridge.start()
            } else {
                bridge.stop()
            }
        }.start()
    }

    private fun pickImage() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "image/*"
        }
        startActivityForResult(intent, REQ_IMAGE)
    }

    private fun ensureDaemon() {
        Thread {
            try {
                val proc = Runtime.getRuntime().exec(arrayOf("su", "-c",
                    "/data/local/tmp/hal_inject/hal_inject_daemon &"))
                proc.waitFor()
            } catch (_: Exception) {}
        }.start()
    }

    // ── View helpers ──────────────────────────────────────────────────────────
    private fun textView(text: String, size: Float, color: Int, bold: Boolean = false) =
        TextView(this).apply {
            this.text = text
            textSize  = size
            setTextColor(color)
            if (bold) setTypeface(null, android.graphics.Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT).also { it.setMargins(0,4,0,4) }
        }

    private fun button(label: String, color: Int = Color.parseColor("#3949ab"), action: () -> Unit) =
        Button(this).apply {
            text = label
            setTextColor(Color.WHITE)
            setBackgroundColor(color)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 120).also { it.setMargins(0, 8, 0, 8) }
            setOnClickListener { action() }
        }

    private fun divider() = View(this).apply {
        setBackgroundColor(Color.DKGRAY)
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
            .also { it.setMargins(0, 8, 0, 8) }
    }

    private fun card(vararg views: View) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(Color.parseColor("#16213e"))
        setPadding(20, 16, 20, 16)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT).also { it.setMargins(0, 8, 0, 8) }
        views.forEach { addView(it) }
    }

    private fun targetRow(pkg: String, label: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity     = Gravity.CENTER_VERTICAL
        setPadding(0, 6, 0, 6)

        val dot = View(context).apply {
            setBackgroundColor(Color.parseColor("#00c853"))
            layoutParams = LinearLayout.LayoutParams(12, 12).also { it.setMargins(0, 0, 12, 0) }
        }
        val tv = TextView(context).apply {
            text = label
            textSize = 12f
            setTextColor(Color.LTGRAY)
        }
        addView(dot)
        addView(tv)
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
