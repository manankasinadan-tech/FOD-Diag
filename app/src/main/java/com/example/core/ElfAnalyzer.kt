package com.example.core

import com.example.model.ElfAnalysis
import java.nio.ByteBuffer
import java.nio.ByteOrder

object ElfAnalyzer {

    private val defaultFodMarkers = listOf(
        "fod", "udfps", "fingerprint", "biometric", "hbm", "lhbm", "illuminat",
        "goodix", "gf_", "fpc", "silead", "focal", "egistec", "qsee", "trustzone",
        "disp_param", "dim", "alpha", "touch", "finger_down", "finger_up",
        "notify", "onacquired", "onfinger", "panel", "drm", "hwcomposer", "sdm"
    )

    fun analyze(
        bytes: ByteArray,
        availableLibraries: Set<String> = emptySet(),
        dynamicKeywords: Set<String> = emptySet()
    ): ElfAnalysis? {
        if (bytes.size < 64) return null
        if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            return null
        }

        val eiClass = bytes[4].toInt() and 0xFF
        val eiData = bytes[5].toInt() and 0xFF
        val is64 = when (eiClass) {
            2 -> true
            1 -> false
            else -> return null
        }
        val order = if (eiData == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val buf = ByteBuffer.wrap(bytes).order(order)

        val eMachine = buf.getShort(18).toInt() and 0xFFFF
        val machineName = when (eMachine) {
            0xB7 -> "AArch64 (arm64-v8a)"
            0x28 -> "ARM (armeabi-v7a)"
            0x3E -> "x86_64"
            0x03 -> "x86"
            0xF3 -> "RISC-V"
            else -> "Arch(0x${eMachine.toString(16)})"
        }

        val shOff = if (is64) buf.getLong(40) else (buf.getInt(32).toLong() and 0xFFFFFFFFL)
        val shEntSize = if (is64) (buf.getShort(58).toInt() and 0xFFFF) else (buf.getShort(46).toInt() and 0xFFFF)
        val shNum = if (is64) (buf.getShort(60).toInt() and 0xFFFF) else (buf.getShort(48).toInt() and 0xFFFF)
        val shStrNdx = if (is64) (buf.getShort(62).toInt() and 0xFFFF) else (buf.getShort(50).toInt() and 0xFFFF)

        data class SectionHeader(
            val nameOff: Int,
            val type: Int,
            val offset: Long,
            val size: Long,
            val link: Int,
            val entSize: Long
        )

        val sections = mutableListOf<SectionHeader>()
        if (shOff > 0 && shEntSize >= (if (is64) 64 else 40) && shNum in 1..2048) {
            for (i in 0 until shNum) {
                val off = (shOff + i.toLong() * shEntSize).toInt()
                if (off < 0 || off + shEntSize > bytes.size) break
                val nameOff = buf.getInt(off)
                val type = buf.getInt(off + 4)
                val secOffset = if (is64) buf.getLong(off + 24) else (buf.getInt(off + 16).toLong() and 0xFFFFFFFFL)
                val secSize = if (is64) buf.getLong(off + 32) else (buf.getInt(off + 20).toLong() and 0xFFFFFFFFL)
                val link = if (is64) buf.getInt(off + 40) else buf.getInt(off + 24)
                val entSize = if (is64) buf.getLong(off + 56) else (buf.getInt(off + 36).toLong() and 0xFFFFFFFFL)
                sections.add(SectionHeader(nameOff, type, secOffset, secSize, link, entSize))
            }
        }

        fun readCString(tableOffset: Int, tableSize: Int, strOffset: Int): String? {
            if (strOffset < 0 || strOffset >= tableSize) return null
            val start = tableOffset + strOffset
            if (start < 0 || start >= bytes.size) return null
            var end = start
            val limit = minOf(bytes.size, tableOffset + tableSize)
            while (end < limit && bytes[end] != 0.toByte()) {
                end++
            }
            return String(bytes, start, end - start, Charsets.UTF_8)
        }

        val shStrSec = sections.getOrNull(shStrNdx)
        fun sectionName(sec: SectionHeader): String {
            if (shStrSec == null) return ""
            return readCString(shStrSec.offset.toInt(), shStrSec.size.toInt(), sec.nameOff).orEmpty()
        }

        val needed = mutableListOf<String>()
        var soName: String? = null
        val fodSymbols = mutableListOf<String>()

        val markers = (defaultFodMarkers + dynamicKeywords.map { it.lowercase() }).distinct()

        // SHT_DYNAMIC = 6
        val dynamicSec = sections.firstOrNull { it.type == 6 }
        if (dynamicSec != null && dynamicSec.link in sections.indices) {
            val strSec = sections[dynamicSec.link]
            val strOff = strSec.offset.toInt()
            val strSize = strSec.size.toInt()
            val dynOff = dynamicSec.offset.toInt()
            val dynEnd = minOf(bytes.size, dynOff + dynamicSec.size.toInt())
            val step = if (is64) 16 else 8
            var pos = dynOff
            while (pos + step <= dynEnd) {
                val tag = if (is64) buf.getLong(pos) else buf.getInt(pos).toLong()
                val value = if (is64) buf.getLong(pos + 8) else (buf.getInt(pos + 4).toLong() and 0xFFFFFFFFL)
                if (tag == 0L) break // DT_NULL
                if (tag == 1L) { // DT_NEEDED
                    readCString(strOff, strSize, value.toInt())?.takeIf { it.isNotBlank() }?.let { needed.add(it) }
                } else if (tag == 14L) { // DT_SONAME
                    soName = readCString(strOff, strSize, value.toInt())
                }
                pos += step
            }
        }

        // SHT_DYNSYM = 11, SHT_SYMTAB = 2
        val symSections = sections.filter { it.type == 11 || it.type == 2 }
        for (symSec in symSections) {
            if (symSec.link !in sections.indices) continue
            val strSec = sections[symSec.link]
            val strOff = strSec.offset.toInt()
            val strSize = strSec.size.toInt()
            val entSize = if (symSec.entSize > 0) symSec.entSize.toInt() else if (is64) 24 else 16
            val start = symSec.offset.toInt()
            val end = minOf(bytes.size, start + symSec.size.toInt())
            var pos = start
            while (pos + entSize <= end && fodSymbols.size < 160) {
                val stName = buf.getInt(pos)
                if (stName > 0) {
                    val symName = readCString(strOff, strSize, stName)
                    if (!symName.isNullOrBlank()) {
                        val lower = symName.lowercase()
                        if (markers.any { lower.contains(it) }) {
                            fodSymbols.add(symName)
                        }
                    }
                }
                pos += entSize
            }
        }

        // Extraction des chaînes ASCII significatives (.rodata / .dynstr / fichier)
        val extractedStrings = extractInterestingStrings(bytes, markers, limit = 120)

        val missing = if (availableLibraries.isNotEmpty()) {
            needed.filter { dep -> !availableLibraries.contains(dep) }
        } else {
            emptyList()
        }

        return ElfAnalysis(
            machine = machineName,
            is64Bit = is64,
            soName = soName,
            neededLibraries = needed.distinct(),
            missingLibraries = missing.distinct(),
            fodSymbols = fodSymbols.distinct(),
            fodStrings = extractedStrings
        )
    }

    private fun extractInterestingStrings(
        bytes: ByteArray,
        markers: List<String>,
        limit: Int
    ): List<String> {
        val results = LinkedHashSet<String>()
        val sb = StringBuilder()
        val scanLimit = minOf(bytes.size, 6 * 1024 * 1024)
        for (i in 0 until scanLimit) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 32..126) {
                if (sb.length < 220) sb.append(b.toChar())
            } else {
                if (sb.length >= 5) {
                    val str = sb.toString()
                    val lower = str.lowercase()
                    if (markers.any { lower.contains(it) } ||
                        lower.startsWith("/sys/") ||
                        lower.startsWith("/dev/") ||
                        lower.startsWith("/vendor/") ||
                        lower.startsWith("vendor.") ||
                        lower.startsWith("ro.") ||
                        lower.startsWith("persist.")
                    ) {
                        results.add(str)
                        if (results.size >= limit) break
                    }
                }
                sb.setLength(0)
            }
        }
        return results.toList()
    }
}
