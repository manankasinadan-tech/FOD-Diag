package com.example.core

import com.example.model.DexRroAnalysis
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

object DexAndRroAnalyzer {

    private val defaultKeywords = listOf(
        "udfps", "fod", "fingerprint", "biometric", "hbm", "lhbm",
        "illuminator", "optical", "dimlayer", "touchfeature", "displayfeature",
        "goodix", "fpc", "silead", "focal", "egistec", "xiaomi", "oplus",
        "oneplus", "lineage", "onfingerdown", "onfingerup"
    )

    fun analyzeApkOrJarBytes(
        sourcePath: String,
        zipBytes: ByteArray,
        dynamicKeywords: Set<String> = emptySet()
    ): DexRroAnalysis? {
        val keywords = (defaultKeywords + dynamicKeywords.map { it.lowercase() }).distinct()
        var packageName: String? = null
        var rroTargetPackage: String? = null
        var rroPriority: Int? = null
        val matchedClasses = LinkedHashSet<String>()
        val matchedMethods = LinkedHashSet<String>()
        val matchedConfigKeys = LinkedHashSet<String>()
        val udfpsProps = LinkedHashMap<String, String>()

        runCatching {
            ZipInputStream(ByteArrayInputStream(zipBytes)).use { zis ->
                while (true) {
                    val entry = zis.nextEntry ?: break
                    val name = entry.name
                    if (!entry.isDirectory) {
                        when {
                            name == "AndroidManifest.xml" -> {
                                val data = readEntryLimited(zis, 2 * 1024 * 1024)
                                val axmlStrings = extractAxmlStrings(data)
                                val manifestInfo = parseManifestOverlayStrings(axmlStrings, data)
                                packageName = manifestInfo.first ?: packageName
                                rroTargetPackage = manifestInfo.second ?: rroTargetPackage
                                rroPriority = manifestInfo.third ?: rroPriority
                                axmlStrings.filter { s -> keywords.any { s.lowercase().contains(it) } }
                                    .take(40)
                                    .forEach { matchedConfigKeys.add(it) }
                            }
                            name == "resources.arsc" -> {
                                val data = readEntryLimited(zis, 8 * 1024 * 1024)
                                val strings = extractArscStrings(data)
                                for (s in strings) {
                                    val lower = s.lowercase()
                                    if (lower.startsWith("config_") && keywords.any { lower.contains(it) }) {
                                        matchedConfigKeys.add(s)
                                    } else if (keywords.any { lower.contains(it) } && s.length in 4..140) {
                                        if (lower.startsWith("/sys/") || lower.startsWith("/dev/") ||
                                            lower.startsWith("vendor.") || lower.startsWith("persist.") ||
                                            lower.startsWith("ro.") || lower.contains("udfps") || lower.contains("fod")
                                        ) {
                                            matchedConfigKeys.add(s)
                                        }
                                    }
                                    if (matchedConfigKeys.size >= 160) break
                                }
                            }
                            name.endsWith(".dex") && name.startsWith("classes") -> {
                                val data = readEntryLimited(zis, 14 * 1024 * 1024)
                                val dexInfo = parseDexFodSymbols(data, keywords)
                                matchedClasses.addAll(dexInfo.first)
                                matchedMethods.addAll(dexInfo.second)
                                dexInfo.third.forEach { (k, v) -> udfpsProps[k] = v }
                            }
                            name.endsWith(".xml") && (name.contains("overlay") || name.contains("fingerprint") || name.contains("udfps") || name.contains("fod")) -> {
                                val data = readEntryLimited(zis, 512 * 1024)
                                extractAxmlStrings(data)
                                    .filter { it.length in 3..140 }
                                    .take(30)
                                    .forEach { matchedConfigKeys.add(it) }
                            }
                        }
                    }
                    zis.closeEntry()
                }
            }
        }

        if (packageName == null && rroTargetPackage == null &&
            matchedClasses.isEmpty() && matchedConfigKeys.isEmpty()
        ) {
            return null
        }

        return DexRroAnalysis(
            sourcePath = sourcePath,
            packageName = packageName,
            rroTargetPackage = rroTargetPackage,
            rroPriority = rroPriority,
            matchedClasses = matchedClasses.take(120),
            matchedMethods = matchedMethods.take(120),
            matchedConfigKeys = matchedConfigKeys.take(120),
            udfpsProperties = udfpsProps
        )
    }

    private fun readEntryLimited(zis: ZipInputStream, maxBytes: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (total < maxBytes) {
            val n = zis.read(buf, 0, minOf(buf.size, maxBytes - total))
            if (n <= 0) break
            out.write(buf, 0, n)
            total += n
        }
        return out.toByteArray()
    }

    /**
     * Parseur DEX minimaliste en lecture seule :
     * lit string_ids, type_ids, method_ids et class_defs pour extraire les classes/méthodes liées au FOD.
     */
    private fun parseDexFodSymbols(
        bytes: ByteArray,
        keywords: List<String>
    ): Triple<List<String>, List<String>, Map<String, String>> {
        val classes = LinkedHashSet<String>()
        val methods = LinkedHashSet<String>()
        val extraProps = LinkedHashMap<String, String>()

        if (bytes.size < 112) return Triple(emptyList(), emptyList(), emptyMap())
        val magic = String(bytes, 0, 4, Charsets.US_ASCII)
        if (magic != "dex\n") return Triple(emptyList(), emptyList(), emptyMap())

        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64)
        val typeIdsOff = buf.getInt(68)
        val methodIdsSize = buf.getInt(88)
        val methodIdsOff = buf.getInt(92)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        fun readMutf8String(stringIdx: Int): String? {
            if (stringIdx < 0 || stringIdx >= stringIdsSize) return null
            val idPos = stringIdsOff + stringIdx * 4
            if (idPos < 0 || idPos + 4 > bytes.size) return null
            var dataOff = buf.getInt(idPos)
            if (dataOff <= 0 || dataOff >= bytes.size) return null
            // Skip ULEB128 utf16_size
            var shift = 0
            while (dataOff < bytes.size && shift < 35) {
                val b = bytes[dataOff++].toInt() and 0xFF
                if ((b and 0x80) == 0) break
                shift += 7
            }
            val start = dataOff
            var end = start
            while (end < bytes.size && end - start < 512 && bytes[end] != 0.toByte()) {
                end++
            }
            return runCatching { String(bytes, start, end - start, Charsets.UTF_8) }.getOrNull()
        }

        fun readTypeDescriptor(typeIdx: Int): String? {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) return null
            val pos = typeIdsOff + typeIdx * 4
            if (pos < 0 || pos + 4 > bytes.size) return null
            val strIdx = buf.getInt(pos)
            return readMutf8String(strIdx)
        }

        // 1. Classes définies dans le DEX
        if (classDefsOff > 0 && classDefsSize in 1..200_000) {
            for (i in 0 until classDefsSize) {
                val pos = classDefsOff + i * 32
                if (pos + 32 > bytes.size) break
                val classTypeIdx = buf.getInt(pos)
                val desc = readTypeDescriptor(classTypeIdx) ?: continue
                val lower = desc.lowercase()
                if (keywords.any { lower.contains(it) }) {
                    classes.add(desc.removePrefix("L").removeSuffix(";").replace('/', '.'))
                    if (classes.size >= 140) break
                }
            }
        }

        // 2. Méthodes FOD / UDFPS / HBM
        if (methodIdsOff > 0 && methodIdsSize in 1..400_000) {
            for (i in 0 until methodIdsSize) {
                val pos = methodIdsOff + i * 8
                if (pos + 8 > bytes.size) break
                val classIdx = buf.getShort(pos).toInt() and 0xFFFF
                val nameIdx = buf.getInt(pos + 4)
                val owner = readTypeDescriptor(classIdx) ?: continue
                val ownerLower = owner.lowercase()
                if (keywords.any { ownerLower.contains(it) }) {
                    val methodName = readMutf8String(nameIdx) ?: continue
                    if (!methodName.startsWith("<") && methodName.length > 2) {
                        val cleanOwner = owner.removePrefix("L").removeSuffix(";").replace('/', '.').substringAfterLast('.')
                        methods.add("$cleanOwner.$methodName()")
                        if (methods.size >= 140) break
                    }
                }
            }
        }

        // 3. Chaînes système liées (sysfs / properties / binder descriptors)
        val scanStrings = minOf(stringIdsSize, 120_000)
        for (i in 0 until scanStrings) {
            val s = readMutf8String(i) ?: continue
            if (s.length in 5..140) {
                val lower = s.lowercase()
                if ((s.startsWith("/sys/") || s.startsWith("/dev/") ||
                            s.startsWith("vendor.") || s.startsWith("persist.") ||
                            s.startsWith("ro.")) && keywords.any { lower.contains(it) }
                ) {
                    extraProps[s] = "Référencé dans DEX"
                    if (extraProps.size >= 40) break
                }
            }
        }

        return Triple(classes.toList(), methods.toList(), extraProps)
    }

    /**
     * Décodeur de pool de chaînes AXML (Android Binary XML).
     */
    private fun extractAxmlStrings(bytes: ByteArray): List<String> {
        if (bytes.size < 16) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val chunkType = buf.getShort(0).toInt() and 0xFFFF
        if (chunkType != 0x0003) return emptyList() // RES_XML_TYPE

        var offset = buf.getShort(2).toInt() and 0xFFFF
        while (offset + 8 <= bytes.size) {
            val type = buf.getShort(offset).toInt() and 0xFFFF
            val headerSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize <= 0 || offset + chunkSize > bytes.size) break
            if (type == 0x0001) { // RES_STRING_POOL_TYPE
                return parseStringPool(bytes, offset, headerSize, chunkSize)
            }
            offset += chunkSize
        }
        return emptyList()
    }

    private fun extractArscStrings(bytes: ByteArray): List<String> {
        if (bytes.size < 20) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val type = buf.getShort(0).toInt() and 0xFFFF
        if (type != 0x0002) return emptyList() // RES_TABLE_TYPE
        var offset = buf.getShort(2).toInt() and 0xFFFF
        val collected = mutableListOf<String>()
        while (offset + 8 <= bytes.size && collected.size < 25_000) {
            val cType = buf.getShort(offset).toInt() and 0xFFFF
            val cHdr = buf.getShort(offset + 2).toInt() and 0xFFFF
            val cSize = buf.getInt(offset + 4)
            if (cSize <= 0 || offset + cSize > bytes.size) break
            if (cType == 0x0001) {
                collected.addAll(parseStringPool(bytes, offset, cHdr, cSize))
            } else if (cType == 0x0200) { // RES_TABLE_PACKAGE_TYPE
                var subOff = offset + cHdr
                val end = offset + cSize
                while (subOff + 8 <= end) {
                    val sType = buf.getShort(subOff).toInt() and 0xFFFF
                    val sHdr = buf.getShort(subOff + 2).toInt() and 0xFFFF
                    val sSize = buf.getInt(subOff + 4)
                    if (sSize <= 0 || subOff + sSize > end) break
                    if (sType == 0x0001) {
                        collected.addAll(parseStringPool(bytes, subOff, sHdr, sSize))
                    }
                    subOff += sSize
                }
            }
            offset += cSize
        }
        return collected
    }

    private fun parseStringPool(
        bytes: ByteArray,
        poolOffset: Int,
        headerSize: Int,
        chunkSize: Int
    ): List<String> {
        if (poolOffset + 28 > bytes.size) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringCount = buf.getInt(poolOffset + 8)
        val flags = buf.getInt(poolOffset + 16)
        val stringsStart = buf.getInt(poolOffset + 20)
        val isUtf8 = (flags and 0x100) != 0

        if (stringCount <= 0 || stringCount > 200_000) return emptyList()
        val offsetsBase = poolOffset + headerSize
        val dataBase = poolOffset + stringsStart
        val poolEnd = minOf(bytes.size, poolOffset + chunkSize)

        val result = ArrayList<String>(minOf(stringCount, 20_000))
        for (i in 0 until minOf(stringCount, 20_000)) {
            val idxPos = offsetsBase + i * 4
            if (idxPos + 4 > poolEnd) break
            val relOff = buf.getInt(idxPos)
            var pos = dataBase + relOff
            if (pos < dataBase || pos >= poolEnd) continue

            val decoded = if (isUtf8) {
                // skip utf16 length (1 or 2 bytes)
                if ((bytes[pos].toInt() and 0x80) != 0) pos += 2 else pos += 1
                if (pos >= poolEnd) continue
                var byteLen = bytes[pos++].toInt() and 0xFF
                if ((byteLen and 0x80) != 0 && pos < poolEnd) {
                    byteLen = ((byteLen and 0x7F) shl 8) or (bytes[pos++].toInt() and 0xFF)
                }
                if (byteLen < 0 || pos + byteLen > poolEnd) continue
                String(bytes, pos, byteLen, Charsets.UTF_8)
            } else {
                if (pos + 2 > poolEnd) continue
                var charLen = buf.getShort(pos).toInt() and 0xFFFF
                pos += 2
                if ((charLen and 0x8000) != 0 && pos + 2 <= poolEnd) {
                    val low = buf.getShort(pos).toInt() and 0xFFFF
                    pos += 2
                    charLen = ((charLen and 0x7FFF) shl 16) or low
                }
                val byteLen = charLen * 2
                if (byteLen < 0 || pos + byteLen > poolEnd) continue
                String(bytes, pos, byteLen, Charsets.UTF_16LE)
            }
            result.add(decoded)
        }
        return result
    }

    private fun parseManifestOverlayStrings(
        strings: List<String>,
        bytes: ByteArray
    ): Triple<String?, String?, Int?> {
        var pkg: String? = null
        var targetPkg: String? = null
        var priority: Int? = null

        val packageCandidates = strings.filter {
            it.contains('.') && !it.contains('/') && !it.contains(' ') &&
                !it.startsWith("http") && !it.startsWith("android.intent") &&
                !it.startsWith("android.permission") && it.length in 5..90
        }

        // Heuristique sûre basée sur la structure AXML START_ELEMENT
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        var offset = buf.getShort(2).toInt() and 0xFFFF
        while (offset + 8 <= bytes.size) {
            val type = buf.getShort(offset).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize <= 0 || offset + chunkSize > bytes.size) break
            if (type == 0x0102 && offset + 36 <= bytes.size) { // RES_XML_START_ELEMENT_TYPE
                val nameIdx = buf.getInt(offset + 20)
                val elemName = strings.getOrNull(nameIdx)
                val attrCount = buf.getShort(offset + 28).toInt() and 0xFFFF
                var attrOff = offset + 36
                for (a in 0 until attrCount) {
                    if (attrOff + 20 > offset + chunkSize) break
                    val attrNameIdx = buf.getInt(attrOff + 4)
                    val attrRawValIdx = buf.getInt(attrOff + 8)
                    val attrType = (buf.getInt(attrOff + 12) ushr 24) and 0xFF
                    val attrData = buf.getInt(attrOff + 16)
                    val attrName = strings.getOrNull(attrNameIdx)

                    if (elemName == "manifest" && attrName == "package") {
                        pkg = strings.getOrNull(attrRawValIdx) ?: strings.getOrNull(attrData)
                    } else if (elemName == "overlay") {
                        if (attrName == "targetPackage") {
                            targetPkg = strings.getOrNull(attrRawValIdx) ?: strings.getOrNull(attrData)
                        } else if (attrName == "priority" && (attrType == 0x10 || attrType == 0x11)) {
                            priority = attrData
                        }
                    }
                    attrOff += 20
                }
            }
            offset += chunkSize
        }

        if (pkg == null) {
            pkg = packageCandidates.firstOrNull { it.contains("overlay") || it.contains("fingerprint") || it.contains("udfps") }
                ?: packageCandidates.firstOrNull()
        }
        return Triple(pkg, targetPkg, priority)
    }
}
