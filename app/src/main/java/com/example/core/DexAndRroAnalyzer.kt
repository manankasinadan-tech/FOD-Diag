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
        val xmlDump = StringBuilder()
        val javaPseudoDump = StringBuilder()

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
                                val decoded = decodeAxmlTree(data, axmlStrings)
                                if (decoded.xml.isNotBlank()) {
                                    xmlDump.appendLine("<!-- $name -->")
                                    xmlDump.appendLine(decoded.xml)
                                }
                                packageName = decoded.packageName ?: packageName
                                rroTargetPackage = decoded.rroTargetPackage ?: rroTargetPackage
                                rroPriority = decoded.rroPriority ?: rroPriority
                                axmlStrings.filter { s -> keywords.any { s.lowercase().contains(it) } }
                                    .take(40)
                                    .forEach { matchedConfigKeys.add(it) }
                            }
                            name == "resources.arsc" -> {
                                val data = readEntryLimited(zis, 10 * 1024 * 1024)
                                val strings = extractArscStrings(data)
                                val configXml = StringBuilder()
                                configXml.appendLine("<!-- Extraits resources.arsc liés FOD/UDFPS -->")
                                configXml.appendLine("<resources>")
                                for (s in strings) {
                                    val lower = s.lowercase()
                                    if ((lower.startsWith("config_") || lower.contains("udfps") || lower.contains("fod") ||
                                                lower.contains("hbm") || lower.contains("fingerprint")) && s.length in 4..140
                                    ) {
                                        matchedConfigKeys.add(s)
                                        configXml.appendLine("    <item name=\"$s\" />")
                                    } else if (keywords.any { lower.contains(it) } && s.length in 4..140) {
                                        if (lower.startsWith("/sys/") || lower.startsWith("/dev/") ||
                                            lower.startsWith("vendor.") || lower.startsWith("persist.") ||
                                            lower.startsWith("ro.")
                                        ) {
                                            matchedConfigKeys.add(s)
                                            configXml.appendLine("    <string>$s</string>")
                                        }
                                    }
                                    if (matchedConfigKeys.size >= 200) break
                                }
                                configXml.appendLine("</resources>")
                                if (matchedConfigKeys.isNotEmpty()) {
                                    xmlDump.appendLine(configXml.toString())
                                }
                            }
                            name.endsWith(".dex") && name.startsWith("classes") -> {
                                val data = readEntryLimited(zis, 16 * 1024 * 1024)
                                val dexInfo = parseDexDetailed(data, keywords)
                                matchedClasses.addAll(dexInfo.classes)
                                matchedMethods.addAll(dexInfo.methods)
                                dexInfo.extraProps.forEach { (k, v) -> udfpsProps[k] = v }
                                if (dexInfo.pseudoJava.isNotBlank() && javaPseudoDump.length < 48_000) {
                                    javaPseudoDump.appendLine("// === $sourcePath :: $name ===")
                                    javaPseudoDump.appendLine(dexInfo.pseudoJava)
                                }
                            }
                            name.endsWith(".xml") && (name.contains("overlay") || name.contains("fingerprint") || name.contains("udfps") || name.contains("fod")) -> {
                                val data = readEntryLimited(zis, 512 * 1024)
                                val strings = extractAxmlStrings(data)
                                val decoded = decodeAxmlTree(data, strings)
                                if (decoded.xml.isNotBlank() && xmlDump.length < 24_000) {
                                    xmlDump.appendLine("<!-- $name -->")
                                    xmlDump.appendLine(decoded.xml)
                                }
                                strings.filter { it.length in 3..140 }.take(30).forEach { matchedConfigKeys.add(it) }
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
            matchedClasses = matchedClasses.take(150),
            matchedMethods = matchedMethods.take(180),
            matchedConfigKeys = matchedConfigKeys.take(180),
            udfpsProperties = udfpsProps,
            decodedRroXml = xmlDump.toString().trim(),
            pseudoSourceCode = javaPseudoDump.toString().trim()
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

    private data class DexDetailedResult(
        val classes: List<String>,
        val methods: List<String>,
        val extraProps: Map<String, String>,
        val pseudoJava: String
    )

    /**
     * Parseur DEX étendu en lecture seule :
     * lit string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs, class_data_item et code_item
     * pour reconstruire un quasi-code Java factuel des classes FOD/UDFPS/HBM/Touch.
     */
    private fun parseDexDetailed(
        bytes: ByteArray,
        keywords: List<String>
    ): DexDetailedResult {
        val classes = LinkedHashSet<String>()
        val methods = LinkedHashSet<String>()
        val extraProps = LinkedHashMap<String, String>()
        val pseudo = StringBuilder()

        if (bytes.size < 112) return DexDetailedResult(emptyList(), emptyList(), emptyMap(), "")
        if (String(bytes, 0, 4, Charsets.US_ASCII) != "dex\n") {
            return DexDetailedResult(emptyList(), emptyList(), emptyMap(), "")
        }

        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64)
        val typeIdsOff = buf.getInt(68)
        val protoIdsSize = buf.getInt(72)
        val protoIdsOff = buf.getInt(76)
        val fieldIdsSize = buf.getInt(80)
        val fieldIdsOff = buf.getInt(84)
        val methodIdsSize = buf.getInt(88)
        val methodIdsOff = buf.getInt(92)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        fun readUleb128(posRef: IntArray): Int {
            var result = 0
            var shift = 0
            while (posRef[0] < bytes.size && shift < 35) {
                val b = bytes[posRef[0]++].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0) break
                shift += 7
            }
            return result
        }

        fun readMutf8String(stringIdx: Int): String? {
            if (stringIdx < 0 || stringIdx >= stringIdsSize) return null
            val idPos = stringIdsOff + stringIdx * 4
            if (idPos < 0 || idPos + 4 > bytes.size) return null
            var dataOff = buf.getInt(idPos)
            if (dataOff <= 0 || dataOff >= bytes.size) return null
            var shift = 0
            while (dataOff < bytes.size && shift < 35) {
                val b = bytes[dataOff++].toInt() and 0xFF
                if ((b and 0x80) == 0) break
                shift += 7
            }
            val start = dataOff
            var end = start
            while (end < bytes.size && end - start < 512 && bytes[end] != 0.toByte()) end++
            return runCatching { String(bytes, start, end - start, Charsets.UTF_8) }.getOrNull()
        }

        fun readTypeDescriptor(typeIdx: Int): String? {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) return null
            val pos = typeIdsOff + typeIdx * 4
            if (pos < 0 || pos + 4 > bytes.size) return null
            return readMutf8String(buf.getInt(pos))
        }

        fun humanType(desc: String?): String {
            if (desc == null) return "Object"
            return when {
                desc == "V" -> "void"
                desc == "Z" -> "boolean"
                desc == "B" -> "byte"
                desc == "S" -> "short"
                desc == "C" -> "char"
                desc == "I" -> "int"
                desc == "J" -> "long"
                desc == "F" -> "float"
                desc == "D" -> "double"
                desc.startsWith("[") -> "${humanType(desc.substring(1))}[]"
                desc.startsWith("L") && desc.endsWith(";") ->
                    desc.substring(1, desc.length - 1).replace('/', '.').substringAfterLast('.')
                else -> desc
            }
        }

        fun readTypeList(offset: Int): List<String> {
            if (offset <= 0 || offset + 4 > bytes.size) return emptyList()
            val count = buf.getInt(offset)
            if (count <= 0 || count > 64 || offset + 4 + count * 2 > bytes.size) return emptyList()
            return (0 until count).mapNotNull { i ->
                val tIdx = buf.getShort(offset + 4 + i * 2).toInt() and 0xFFFF
                readTypeDescriptor(tIdx)
            }
        }

        fun readMethodSignature(methodIdx: Int): Triple<String, String, String>? {
            if (methodIdx < 0 || methodIdx >= methodIdsSize) return null
            val pos = methodIdsOff + methodIdx * 8
            if (pos < 0 || pos + 8 > bytes.size) return null
            val classIdx = buf.getShort(pos).toInt() and 0xFFFF
            val protoIdx = buf.getShort(pos + 2).toInt() and 0xFFFF
            val nameIdx = buf.getInt(pos + 4)

            val owner = humanType(readTypeDescriptor(classIdx))
            val mName = readMutf8String(nameIdx) ?: return null
            if (protoIdx < 0 || protoIdx >= protoIdsSize) return Triple(owner, "void", "$mName()")
            val pPos = protoIdsOff + protoIdx * 12
            if (pPos < 0 || pPos + 12 > bytes.size) return Triple(owner, "void", "$mName()")
            val retIdx = buf.getInt(pPos + 4)
            val paramsOff = buf.getInt(pPos + 8)
            val retType = humanType(readTypeDescriptor(retIdx))
            val params = readTypeList(paramsOff).mapIndexed { i, t -> "${humanType(t)} arg$i" }
            return Triple(owner, retType, "$mName(${params.joinToString(", ")})")
        }

        fun readFieldSignature(fieldIdx: Int): Triple<String, String, String>? {
            if (fieldIdx < 0 || fieldIdx >= fieldIdsSize) return null
            val pos = fieldIdsOff + fieldIdx * 8
            if (pos < 0 || pos + 8 > bytes.size) return null
            val classIdx = buf.getShort(pos).toInt() and 0xFFFF
            val typeIdx = buf.getShort(pos + 2).toInt() and 0xFFFF
            val nameIdx = buf.getInt(pos + 4)
            val owner = humanType(readTypeDescriptor(classIdx))
            val fType = humanType(readTypeDescriptor(typeIdx))
            val fName = readMutf8String(nameIdx) ?: return null
            return Triple(owner, fType, fName)
        }

        fun extractCodeInsights(codeOff: Int): List<String> {
            if (codeOff <= 0 || codeOff + 16 > bytes.size) return emptyList()
            val insnsSize = buf.getInt(codeOff + 12) // en unités de 16 bits
            val insnsStart = codeOff + 16
            if (insnsSize <= 0 || insnsSize > 12_000 || insnsStart + insnsSize * 2 > bytes.size) return emptyList()

            val calls = LinkedHashSet<String>()
            val literals = LinkedHashSet<String>()
            var ip = 0
            while (ip < insnsSize && (calls.size + literals.size) < 18) {
                val unit = buf.getShort(insnsStart + ip * 2).toInt() and 0xFFFF
                val op = unit and 0xFF
                when (op) {
                    // const-string (0x1A: 21c, 2 units)
                    0x1A -> if (ip + 1 < insnsSize) {
                        val sIdx = buf.getShort(insnsStart + (ip + 1) * 2).toInt() and 0xFFFF
                        val str = readMutf8String(sIdx)
                        if (!str.isNullOrBlank() && str.length in 2..100) {
                            literals.add("\"${str.replace("\n", "\\n")}\"")
                        }
                        ip += 2
                    } else break
                    // const-string/jumbo (0x1B: 31c, 3 units)
                    0x1B -> if (ip + 2 < insnsSize) {
                        val sIdx = buf.getInt(insnsStart + (ip + 1) * 2)
                        val str = readMutf8String(sIdx)
                        if (!str.isNullOrBlank() && str.length in 2..100) {
                            literals.add("\"${str.replace("\n", "\\n")}\"")
                        }
                        ip += 3
                    } else break
                    // invoke-virtual/super/direct/static/interface (0x6E..0x72: 35c, 3 units)
                    in 0x6E..0x72 -> if (ip + 2 < insnsSize) {
                        val mIdx = buf.getShort(insnsStart + (ip + 1) * 2).toInt() and 0xFFFF
                        readMethodSignature(mIdx)?.let { (owner, _, sig) ->
                            val cleanSig = sig.substringBefore("(") + "()"
                            calls.add("$owner.$cleanSig")
                        }
                        ip += 3
                    } else break
                    // iget/sget/iput/sput (0x52..0x6D: 22c/21c, 2 units)
                    in 0x52..0x6D -> if (ip + 1 < insnsSize) {
                        val fIdx = buf.getShort(insnsStart + (ip + 1) * 2).toInt() and 0xFFFF
                        readFieldSignature(fIdx)?.let { (owner, _, fName) ->
                            val fl = fName.lowercase()
                            if (keywords.any { fl.contains(it) || owner.lowercase().contains(it) }) {
                                calls.add("field $owner.$fName")
                            }
                        }
                        ip += 2
                    } else break
                    else -> ip += dalvikInstructionLengthUnits(op)
                }
            }
            val out = mutableListOf<String>()
            if (literals.isNotEmpty()) out.add("chaînes: ${literals.take(6).joinToString(", ")}")
            if (calls.isNotEmpty()) out.add("appels: ${calls.take(8).joinToString(" -> ")}")
            return out
        }

        // Parcourir class_defs et reconstruire les classes FOD/UDFPS en quasi-code Java
        var emittedClasses = 0
        if (classDefsOff > 0 && classDefsSize in 1..250_000) {
            for (i in 0 until classDefsSize) {
                val pos = classDefsOff + i * 32
                if (pos + 32 > bytes.size) break
                val classTypeIdx = buf.getInt(pos)
                val accessFlags = buf.getInt(pos + 4)
                val superclassIdx = buf.getInt(pos + 8)
                val interfacesOff = buf.getInt(pos + 12)
                val classDataOff = buf.getInt(pos + 24)

                val desc = readTypeDescriptor(classTypeIdx) ?: continue
                val lower = desc.lowercase()
                if (!keywords.any { lower.contains(it) }) continue

                val fqcn = desc.removePrefix("L").removeSuffix(";").replace('/', '.')
                classes.add(fqcn)

                if (emittedClasses < 30 && classDataOff > 0 && classDataOff < bytes.size) {
                    emittedClasses++
                    val pkg = fqcn.substringBeforeLast('.', "")
                    val simpleName = fqcn.substringAfterLast('.')
                    val superName = if (superclassIdx >= 0) humanType(readTypeDescriptor(superclassIdx)) else "Object"
                    val ifaces = readTypeList(interfacesOff).map { humanType(it) }
                    val kind = if ((accessFlags and 0x0200) != 0) "interface" else "class"

                    pseudo.appendLine("// Package: $pkg")
                    pseudo.append("public $kind $simpleName")
                    if (kind == "class" && superName != "Object") pseudo.append(" extends $superName")
                    if (ifaces.isNotEmpty()) pseudo.append(" implements ${ifaces.joinToString(", ")}")
                    pseudo.appendLine(" {")

                    val cursor = intArrayOf(classDataOff)
                    val staticFieldsSize = readUleb128(cursor)
                    val instanceFieldsSize = readUleb128(cursor)
                    val directMethodsSize = readUleb128(cursor)
                    val virtualMethodsSize = readUleb128(cursor)

                    var fieldIdx = 0
                    val totalFields = staticFieldsSize + instanceFieldsSize
                    for (f in 0 until minOf(totalFields, 100)) {
                        val diff = readUleb128(cursor)
                        readUleb128(cursor) // flags
                        fieldIdx += diff
                        if (f < 25) {
                            readFieldSignature(fieldIdx)?.let { (_, fType, fName) ->
                                val prefix = if (f < staticFieldsSize) "static " else ""
                                pseudo.appendLine("    ${prefix}$fType $fName;")
                            }
                        }
                    }

                    var methodIdx = 0
                    for (m in 0 until directMethodsSize) {
                        val diff = readUleb128(cursor)
                        val mFlags = readUleb128(cursor)
                        val codeOff = readUleb128(cursor)
                        methodIdx += diff
                        if (m < 35) {
                            readMethodSignature(methodIdx)?.let { (_, retType, sig) ->
                                val methodNameOnly = sig.substringBefore('(')
                                methods.add("$simpleName.$methodNameOnly()")
                                val mod = if ((mFlags and 0x0008) != 0) "static " else ""
                                val insights = if (codeOff > 0) extractCodeInsights(codeOff) else emptyList()
                                if (insights.isEmpty()) {
                                    pseudo.appendLine("    $mod$retType $sig {}")
                                } else {
                                    pseudo.appendLine("    $mod$retType $sig {")
                                    insights.forEach { pseudo.appendLine("        // $it") }
                                    pseudo.appendLine("    }")
                                }
                            }
                        }
                    }

                    methodIdx = 0
                    for (m in 0 until virtualMethodsSize) {
                        val diff = readUleb128(cursor)
                        val mFlags = readUleb128(cursor)
                        val codeOff = readUleb128(cursor)
                        methodIdx += diff
                        if (m < 45) {
                            readMethodSignature(methodIdx)?.let { (_, retType, sig) ->
                                val methodNameOnly = sig.substringBefore('(')
                                methods.add("$simpleName.$methodNameOnly()")
                                val mod = if ((mFlags and 0x0400) != 0) "abstract " else ""
                                val insights = if (codeOff > 0) extractCodeInsights(codeOff) else emptyList()
                                if (insights.isEmpty()) {
                                    pseudo.appendLine("    $mod$retType $sig {}")
                                } else {
                                    pseudo.appendLine("    $mod$retType $sig {")
                                    insights.forEach { pseudo.appendLine("        // $it") }
                                    pseudo.appendLine("    }")
                                }
                            }
                        }
                    }
                    pseudo.appendLine("}")
                    pseudo.appendLine()
                }
            }
        }

        // Chaînes système référencées dans le DEX
        val scanStrings = minOf(stringIdsSize, 140_000)
        for (i in 0 until scanStrings) {
            val s = readMutf8String(i) ?: continue
            if (s.length in 5..140) {
                val lower = s.lowercase()
                if ((s.startsWith("/sys/") || s.startsWith("/dev/") ||
                            s.startsWith("vendor.") || s.startsWith("persist.") ||
                            s.startsWith("ro.")) && keywords.any { lower.contains(it) }
                ) {
                    extraProps[s] = "Référencé dans DEX"
                    if (extraProps.size >= 50) break
                }
            }
        }

        return DexDetailedResult(
            classes = classes.toList(),
            methods = methods.toList(),
            extraProps = extraProps,
            pseudoJava = pseudo.toString()
        )
    }

    private fun dalvikInstructionLengthUnits(op: Int): Int {
        return when (op) {
            in 0x00..0x01, 0x04, 0x07, in 0x0A..0x12, in 0x1D..0x1E, 0x21, in 0x27..0x28,
            in 0x3E..0x43, in 0x7B..0x8F, in 0xB0..0xCF -> 1
            0x18, 0x26, 0x2B, 0x2C -> 3
            in 0x13..0x17, 0x19, in 0x1C..0x1C, in 0x1F..0x20, in 0x22..0x23, 0x29,
            in 0x2D..0x3D, in 0x44..0x6D, in 0x90..0xAF, in 0xD0..0xE2 -> 2
            in 0x24..0x25, 0x2A, in 0x6E..0x78 -> 3
            else -> 1
        }
    }

    private data class DecodedAxmlTree(
        val packageName: String?,
        val rroTargetPackage: String?,
        val rroPriority: Int?,
        val xml: String
    )

    private fun decodeAxmlTree(bytes: ByteArray, strings: List<String>): DecodedAxmlTree {
        if (bytes.size < 16 || strings.isEmpty()) return DecodedAxmlTree(null, null, null, "")
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val chunkType = buf.getShort(0).toInt() and 0xFFFF
        if (chunkType != 0x0003) return DecodedAxmlTree(null, null, null, "")

        var pkg: String? = null
        var targetPkg: String? = null
        var priority: Int? = null
        val xml = StringBuilder()
        var indent = 0

        var offset = buf.getShort(2).toInt() and 0xFFFF
        while (offset + 8 <= bytes.size) {
            val type = buf.getShort(offset).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize <= 0 || offset + chunkSize > bytes.size) break
            when (type) {
                0x0102 -> if (offset + 36 <= bytes.size) {
                    val nameIdx = buf.getInt(offset + 20)
                    val elemName = strings.getOrNull(nameIdx) ?: "node"
                    val attrCount = buf.getShort(offset + 28).toInt() and 0xFFFF
                    val attrs = mutableListOf<String>()
                    var attrOff = offset + 36
                    for (a in 0 until attrCount) {
                        if (attrOff + 20 > offset + chunkSize) break
                        val attrNameIdx = buf.getInt(attrOff + 4)
                        val attrRawValIdx = buf.getInt(attrOff + 8)
                        val attrType = (buf.getInt(attrOff + 12) ushr 24) and 0xFF
                        val attrData = buf.getInt(attrOff + 16)
                        val attrName = strings.getOrNull(attrNameIdx) ?: "attr"
                        val attrVal = when (attrType) {
                            0x03 -> strings.getOrNull(attrRawValIdx) ?: strings.getOrNull(attrData) ?: ""
                            0x10 -> attrData.toString()
                            0x11 -> "0x${attrData.toString(16)}"
                            0x12 -> (attrData != 0).toString()
                            else -> strings.getOrNull(attrRawValIdx) ?: "0x${attrData.toString(16)}"
                        }
                        attrs.add("$attrName=\"$attrVal\"")
                        if (elemName == "manifest" && attrName == "package") pkg = attrVal
                        if (elemName == "overlay") {
                            if (attrName == "targetPackage") targetPkg = attrVal
                            if (attrName == "priority" && (attrType == 0x10 || attrType == 0x11)) priority = attrData
                        }
                        attrOff += 20
                    }
                    val pad = "  ".repeat(indent.coerceAtMost(8))
                    if (attrs.isEmpty()) {
                        xml.appendLine("$pad<$elemName>")
                    } else {
                        xml.appendLine("$pad<$elemName ${attrs.joinToString(" ")}>")
                    }
                    indent++
                }
                0x0103 -> if (offset + 24 <= bytes.size) {
                    indent = (indent - 1).coerceAtLeast(0)
                    val nameIdx = buf.getInt(offset + 20)
                    val elemName = strings.getOrNull(nameIdx) ?: "node"
                    xml.appendLine("${"  ".repeat(indent.coerceAtMost(8))}</$elemName>")
                }
            }
            offset += chunkSize
        }
        return DecodedAxmlTree(pkg, targetPkg, priority, xml.toString().take(8000))
    }

    private fun extractAxmlStrings(bytes: ByteArray): List<String> {
        if (bytes.size < 16) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if ((buf.getShort(0).toInt() and 0xFFFF) != 0x0003) return emptyList()
        var offset = buf.getShort(2).toInt() and 0xFFFF
        while (offset + 8 <= bytes.size) {
            val type = buf.getShort(offset).toInt() and 0xFFFF
            val headerSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize <= 0 || offset + chunkSize > bytes.size) break
            if (type == 0x0001) return parseStringPool(bytes, offset, headerSize, chunkSize)
            offset += chunkSize
        }
        return emptyList()
    }

    private fun extractArscStrings(bytes: ByteArray): List<String> {
        if (bytes.size < 20) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if ((buf.getShort(0).toInt() and 0xFFFF) != 0x0002) return emptyList()
        var offset = buf.getShort(2).toInt() and 0xFFFF
        val collected = mutableListOf<String>()
        while (offset + 8 <= bytes.size && collected.size < 25_000) {
            val cType = buf.getShort(offset).toInt() and 0xFFFF
            val cHdr = buf.getShort(offset + 2).toInt() and 0xFFFF
            val cSize = buf.getInt(offset + 4)
            if (cSize <= 0 || offset + cSize > bytes.size) break
            if (cType == 0x0001) {
                collected.addAll(parseStringPool(bytes, offset, cHdr, cSize))
            } else if (cType == 0x0200) {
                var subOff = offset + cHdr
                val end = offset + cSize
                while (subOff + 8 <= end) {
                    val sType = buf.getShort(subOff).toInt() and 0xFFFF
                    val sHdr = buf.getShort(subOff + 2).toInt() and 0xFFFF
                    val sSize = buf.getInt(subOff + 4)
                    if (sSize <= 0 || subOff + sSize > end) break
                    if (sType == 0x0001) collected.addAll(parseStringPool(bytes, subOff, sHdr, sSize))
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
}
