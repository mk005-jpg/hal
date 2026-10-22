package com.secpen.halinject

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import org.json.JSONObject
import java.io.*
import java.util.concurrent.atomic.AtomicBoolean

private const val TAG = "DaemonBridge"
private const val SOCK = "/data/local/tmp/hal_inject/daemon.sock"

data class DaemonStatus(
    val connected: Boolean = false,
    val active: Boolean    = false,
    val fridaPid: Int      = -1,
    val backNode: String   = "",
    val imagePath: String  = "",
    val fit: String        = "cover"
)

class DaemonBridge {

    private val running = AtomicBoolean(false)
    var onStatus: ((DaemonStatus) -> Unit)? = null

    // ── One-shot command ───────────────────────────────────────────────────────
    private fun send(cmd: String): String {
        return try {
            val sock = LocalSocket()
            sock.connect(LocalSocketAddress(SOCK, LocalSocketAddress.Namespace.FILESYSTEM))
            sock.outputStream.write((cmd + "\n").toByteArray())
            sock.outputStream.flush()
            val line = BufferedReader(InputStreamReader(sock.inputStream)).readLine() ?: "ERROR no response"
            sock.close()
            line
        } catch (e: Exception) {
            Log.e(TAG, "send($cmd): ${e.message}")
            "ERROR ${e.message}"
        }
    }

    fun setImage(path: String): Boolean = send("SET_IMAGE $path").startsWith("OK")

    /** Re-place the staged image with a new fit mode: cover|contain|stretch. */
    fun place(fit: String): Boolean = send("PLACE $fit").startsWith("OK")

    fun start(): Boolean = send("START").startsWith("OK")

    fun stop(): Boolean = send("STOP").startsWith("OK")

    fun backNode(): String = send("BACK_NODE").trim()

    fun fetchStatus(): DaemonStatus {
        val resp = send("STATUS")
        if (!resp.startsWith("STATUS ")) return DaemonStatus(connected = false)
        return try {
            val json = JSONObject(resp.removePrefix("STATUS ").trim())
            DaemonStatus(
                connected  = true,
                active     = json.optBoolean("active", false),
                fridaPid   = json.optInt("frida_pid", -1),
                backNode   = json.optString("back_node", ""),
                imagePath  = json.optString("image", ""),
                fit        = json.optString("fit", "cover")
            )
        } catch (e: Exception) {
            DaemonStatus(connected = false)
        }
    }

    // ── Polling thread ────────────────────────────────────────────────────────
    fun startPolling() {
        if (running.getAndSet(true)) return
        Thread {
            while (running.get()) {
                val s = fetchStatus()
                onStatus?.invoke(s)
                Thread.sleep(1500)
            }
        }.also { it.isDaemon = true }.start()
    }

    fun stopPolling() { running.set(false) }
}
