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

    private val importantSystemImports = setOf(
        "ioctl", "open", "openat", "close", "read", "write", "mmap", "poll",
        "epoll_wait", "dlopen", "dlsym", "property_get", "property_set",
        "__system_property_get", "__android_log_print", "pthread_create"
    )

    fun analyze(
        bytes: ByteArray,
        availableLibraries: Map<String, String> = emptyMap(),
        dynamicKeywords: Set<String> = emptySet(),
        sourcePath: String = ""
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

        data class SectionHeader(
            val type: Int,
            val offset: Long,
            val size: Long,
            val link: Int,
            val entSize: Long
        )

        val sections = mutableListOf<SectionHeader>()
        if (shOff > 0 && shEntSize >= (if (is64) 64 else 40) && shNum in 1..4096) {
            for (i in 0 until shNum) {
                val off = (shOff + i.toLong() * shEntSize).toInt()
                if (off < 0 || off + shEntSize > bytes.size) break
                val type = buf.getInt(off + 4)
                val secOffset = if (is64) buf.getLong(off + 24) else (buf.getInt(off + 16).toLong() and 0xFFFFFFFFL)
                val secSize = if (is64) buf.getLong(off + 32) else (buf.getInt(off + 20).toLong() and 0xFFFFFFFFL)
                val link = if (is64) buf.getInt(off + 40) else buf.getInt(off + 24)
                val entSize = if (is64) buf.getLong(off + 56) else (buf.getInt(off + 36).toLong() and 0xFFFFFFFFL)
                sections.add(SectionHeader(type, secOffset, secSize, link, entSize))
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

        val needed = mutableListOf<String>()
        var soName: String? = null
        val fodSymbols = LinkedHashSet<String>()
        val exportedSymbols = LinkedHashSet<String>()
        val importedSymbols = LinkedHashSet<String>()
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
                if (tag == 0L) break
                if (tag == 1L) {
                    readCString(strOff, strSize, value.toInt())?.takeIf { it.isNotBlank() }?.let { needed.add(it) }
                } else if (tag == 14L) {
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
            while (pos + entSize <= end) {
                val stName = buf.getInt(pos)
                val stInfo = if (is64) (bytes[pos + 4].toInt() and 0xFF) else (bytes[pos + 12].toInt() and 0xFF)
                val stShndx = if (is64) (buf.getShort(pos + 6).toInt() and 0xFFFF) else (buf.getShort(pos + 14).toInt() and 0xFFFF)
                val symType = stInfo and 0x0F
                if (stName > 0 && (symType == 0 || symType == 1 || symType == 2)) {
                    val rawSym = readCString(strOff, strSize, stName)
                    if (!rawSym.isNullOrBlank()) {
                        val readable = demangleItaniumSymbol(rawSym)
                        val lower = readable.lowercase()
                        val isFodRelated = markers.any { lower.contains(it) }
                        if (stShndx == 0) {
                            // UND: symbole importé
                            if (isFodRelated || importantSystemImports.contains(rawSym) || lower.contains("binder") || lower.contains("hidl") || lower.contains("aidl")) {
                                if (importedSymbols.size < 160) importedSymbols.add(readable)
                            }
                        } else {
                            // Exporté / défini dans ce binaire
                            if (isFodRelated && exportedSymbols.size < 200) {
                                exportedSymbols.add(readable)
                            } else if (exportedSymbols.size < 45 && !rawSym.startsWith("_ZSt") && !rawSym.startsWith("__")) {
                                exportedSymbols.add(readable)
                            }
                        }
                        if (isFodRelated && fodSymbols.size < 220) {
                            fodSymbols.add(readable)
                        }
                    }
                }
                pos += entSize
            }
        }

        val extractedStrings = extractInterestingStrings(bytes, markers, limit = 180)

        val resolvedDeps = LinkedHashMap<String, String>()
        val missing = mutableListOf<String>()
        if (availableLibraries.isNotEmpty()) {
            for (dep in needed.distinct()) {
                val resolved = availableLibraries[dep]
                if (resolved != null) {
                    resolvedDeps[dep] = resolved
                } else {
                    missing.add(dep)
                }
            }
        }

        val pseudoCpp = buildPseudoCppSource(
            sourcePath = sourcePath,
            soName = soName,
            machine = machineName,
            needed = needed.distinct(),
            resolvedDeps = resolvedDeps,
            missing = missing.distinct(),
            imported = importedSymbols.toList(),
            exported = exportedSymbols.toList(),
            strings = extractedStrings
        )

        return ElfAnalysis(
            machine = machineName,
            is64Bit = is64,
            soName = soName,
            neededLibraries = needed.distinct(),
            resolvedDependencies = resolvedDeps,
            missingLibraries = missing.distinct(),
            fodSymbols = fodSymbols.toList(),
            exportedSymbols = exportedSymbols.toList(),
            importedSymbols = importedSymbols.toList(),
            fodStrings = extractedStrings,
            pseudoSourceCode = pseudoCpp
        )
    }

    private fun buildPseudoCppSource(
        sourcePath: String,
        soName: String?,
        machine: String,
        needed: List<String>,
        resolvedDeps: Map<String, String>,
        missing: List<String>,
        imported: List<String>,
        exported: List<String>,
        strings: List<String>
    ): String {
        val sb = StringBuilder()
        sb.appendLine("/*")
        sb.appendLine(" * RECONSTRUCTION QUASI-CODE SOURCE C/C++ (100% FACTUELLE)")
        sb.appendLine(" * Binaire : ${sourcePath.ifBlank { soName ?: "ELF" }}")
        sb.appendLine(" * Architecture : $machine | SONAME : ${soName ?: "non défini"}")
        sb.appendLine(" */")
        sb.appendLine()
        sb.appendLine("// === 1. Dépendances dynamiques (DT_NEEDED) ===")
        needed.forEach { dep ->
            val path = resolvedDeps[dep]
            if (path != null) {
                sb.appendLine("#include <$dep> // Résolu : $path")
            } else if (missing.contains(dep)) {
                sb.appendLine("#error \"Dépendance manquante : $dep\"")
            } else {
                sb.appendLine("#include <$dep>")
            }
        }
        sb.appendLine()

        val sysNodes = strings.filter { it.startsWith("/sys/") || it.startsWith("/dev/") || it.startsWith("/proc/") }
        val props = strings.filter { it.startsWith("ro.") || it.startsWith("persist.") || it.startsWith("vendor.") }
        val halIfaces = strings.filter { it.contains("hardware.") || it.contains("IFingerprint") || it.contains("IBiometrics") || it.contains("@") }

        if (sysNodes.isNotEmpty() || props.isNotEmpty() || halIfaces.isNotEmpty()) {
            sb.appendLine("// === 2. Constantes matérielles, sysfs, propriétés & interfaces (.rodata) ===")
            sysNodes.take(25).forEachIndexed { idx, s ->
                sb.appendLine("static constexpr const char* SYS_NODE_$idx = \"$s\";")
            }
            props.take(25).forEachIndexed { idx, s ->
                sb.appendLine("static constexpr const char* PROP_KEY_$idx = \"$s\";")
            }
            halIfaces.take(20).forEachIndexed { idx, s ->
                sb.appendLine("static constexpr const char* HAL_IFACE_$idx = \"$s\";")
            }
            sb.appendLine()
        }

        if (imported.isNotEmpty()) {
            sb.appendLine("// === 3. Appels système & symboles externes importés (UND) ===")
            imported.take(45).forEach { sym ->
                sb.appendLine("extern \"C++\" auto $sym(...);")
            }
            sb.appendLine()
        }

        if (exported.isNotEmpty()) {
            sb.appendLine("// === 4. Fonctions & méthodes implémentées / exportées (.dynsym) ===")
            exported.take(65).forEach { sym ->
                sb.appendLine("void $sym(/* paramètres ABI */) { /* implémenté dans ${soName ?: "ce binaire"} */ }")
            }
        }
        return sb.toString()
    }

    /**
     * Démangleur léger Itanium C++ ABI (_Z...) pour rendre les symboles ELF lisibles comme du code C++.
     */
    fun demangleItaniumSymbol(raw: String): String {
        if (!raw.startsWith("_Z")) return raw
        return runCatching {
            var idx = 2
            if (idx < raw.length && raw[idx] == 'N') {
                idx++
                // Ignorer qualificateurs CV/ref initiaux éventuels (K, V, R, O)
                while (idx < raw.length && raw[idx] in listOf('K', 'V', 'r', 'R', 'O')) idx++
                val parts = mutableListOf<String>()
                while (idx < raw.length && raw[idx] != 'E') {
                    if (raw[idx] == 'C' && idx + 1 < raw.length && raw[idx + 1].isDigit()) {
                        parts.add(parts.lastOrNull() ?: "ctor")
                        idx += 2
                        continue
                    }
                    if (raw[idx] == 'D' && idx + 1 < raw.length && raw[idx + 1].isDigit()) {
                        parts.add("~${parts.lastOrNull() ?: "dtor"}")
                        idx += 2
                        continue
                    }
                    if (!raw[idx].isDigit()) break
                    var len = 0
                    while (idx < raw.length && raw[idx].isDigit()) {
                        len = len * 10 + (raw[idx] - '0')
                        idx++
                    }
                    if (len <= 0 || idx + len > raw.length) break
                    parts.add(raw.substring(idx, idx + len))
                    idx += len
                }
                if (parts.isNotEmpty()) return@runCatching parts.joinToString("::")
            } else if (idx < raw.length && raw[idx].isDigit()) {
                var len = 0
                while (idx < raw.length && raw[idx].isDigit()) {
                    len = len * 10 + (raw[idx] - '0')
                    idx++
                }
                if (len > 0 && idx + len <= raw.length) {
                    return@runCatching raw.substring(idx, idx + len)
                }
            }
            raw
        }.getOrDefault(raw)
    }

    private fun extractInterestingStrings(
        bytes: ByteArray,
        markers: List<String>,
        limit: Int
    ): List<String> {
        val results = LinkedHashSet<String>()
        val sb = StringBuilder()
        val scanLimit = minOf(bytes.size, 8 * 1024 * 1024)
        for (i in 0 until scanLimit) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 32..126) {
                if (sb.length < 220) sb.append(b.toChar())
            } else {
                if (sb.length >= 4) {
                    val str = sb.toString()
                    val lower = str.lowercase()
                    if (markers.any { lower.contains(it) } ||
                        lower.startsWith("/sys/") ||
                        lower.startsWith("/dev/") ||
                        lower.startsWith("/proc/") ||
                        lower.startsWith("/vendor/") ||
                        lower.startsWith("/odm/") ||
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
