package com.secpen.halinject

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Rect
import android.graphics.YuvImage
import android.net.Uri
import java.io.*
import java.nio.ByteBuffer

object ImagePrep {

    private const val NV21_W = 1280
    private const val NV21_H = 720

    fun prepare(ctx: Context, uri: Uri): String? {
        return try {
            val dir = File("/data/local/tmp/hal_inject").also { it.mkdirs() }
            val jpeg = File(dir, "frame.jpg")

            // Copy JPEG to working dir
            ctx.contentResolver.openInputStream(uri)?.use { src ->
                FileOutputStream(jpeg).use { dst -> src.copyTo(dst) }
            } ?: return null

            // Decode and re-encode to ensure valid JPEG
            val bmp = BitmapFactory.decodeFile(jpeg.absolutePath)
                ?: return jpeg.absolutePath

            FileOutputStream(jpeg).use { out ->
                bmp.compress(Bitmap.CompressFormat.JPEG, 90, out)
            }

            // Generate NV21 for YUV streams
            val nv21File = File(dir, "frame.nv21")
            val scaled = Bitmap.createScaledBitmap(bmp, NV21_W, NV21_H, true)
            writeNv21(scaled, nv21File)

            bmp.recycle()
            scaled.recycle()
            jpeg.absolutePath
        } catch (e: Exception) {
            null
        }
    }

    private fun writeNv21(bmp: Bitmap, out: File) {
        val w = bmp.width; val h = bmp.height
        val argb = IntArray(w * h)
        bmp.getPixels(argb, 0, w, 0, 0, w, h)

        val nv21 = ByteArray(w * h * 3 / 2)
        argbToNv21(argb, w, h, nv21)
        FileOutputStream(out).use { it.write(nv21) }
    }

    private fun argbToNv21(argb: IntArray, w: Int, h: Int, nv21: ByteArray) {
        var yIndex = 0
        var uvIndex = w * h
        for (j in 0 until h) {
            for (i in 0 until w) {
                val pixel = argb[j * w + i]
                val r = (pixel shr 16) and 0xFF
                val g = (pixel shr 8)  and 0xFF
                val b =  pixel         and 0xFF
                val y  = (( 66 * r + 129 * g +  25 * b + 128) shr 8) + 16
                val cr = (( 112 * r - 94 * g -  18 * b + 128) shr 8) + 128
                val cb = ((-38 * r - 74 * g + 112 * b + 128) shr 8) + 128
                nv21[yIndex++] = y.coerceIn(0, 255).toByte()
                if (j % 2 == 0 && i % 2 == 0 && uvIndex + 1 < nv21.size) {
                    nv21[uvIndex++] = cr.coerceIn(0, 255).toByte()
                    nv21[uvIndex++] = cb.coerceIn(0, 255).toByte()
                }
            }
        }
    }
}
