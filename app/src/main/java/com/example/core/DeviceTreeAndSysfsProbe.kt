package com.example.core

import com.example.model.DeviceTreeNode
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class SysfsDiscoveredNode(
    val path: String,
    val category: String,
    val permissions: String,
    val seLinuxContext: String,
    val readableValue: String
)

class DeviceTreeAndSysfsProbe(private val shell: RootShellExecutor) {

    suspend fun probeDeviceTree(dynamicKeywords: Set<String>): List<DeviceTreeNode> {
        val kwPattern = (listOf(
            "finger", "fod", "udfps", "biometric", "goodix", "gf_", "fpc",
            "silead", "focal", "egistec", "dsi", "panel", "oled", "amoled",
            "hbm", "lhbm", "backlight", "touch", "synaptics", "novatek",
            "fts", "gt9", "sec_ts", "ilitek", "haptics"
        ) + dynamicKeywords.map { it.lowercase() })
            .distinct()
            .filter { it.length >= 3 }
            .joinToString("|") { Regex.escape(it) }

        val findCmd = "if [ -r /proc/device-tree ] || [ \$(id -u) -eq 0 ]; then find /proc/device-tree -maxdepth 6 -type d 2>/dev/null | grep -iE '$kwPattern' | head -n 75; fi"
        val dirsRes = shell.exec(findCmd, preferRoot = true, timeoutMs = 14_000L)
        val dirs = dirsRes.stdout.lines().map { it.trim() }.filter { it.startsWith("/proc/device-tree") }.distinct()

        val nodes = mutableListOf<DeviceTreeNode>()
        for (dir in dirs) {
            val propsRes = shell.exec("ls -1 ${RootShellExecutor.shellQuote(dir)} 2>/dev/null | head -n 45", preferRoot = true, timeoutMs = 4_000L)
            val propNames = propsRes.stdout.lines().map { it.trim() }.filter { it.isNotBlank() }
            val propMap = LinkedHashMap<String, String>()
            var compatible: String? = null

            for (prop in propNames) {
                val propPath = "$dir/$prop"
                val bytes = shell.readFileBytesSafe(propPath, maxBytes = 4096, preferRoot = true) ?: continue
                if (bytes.isEmpty()) {
                    propMap[prop] = "<booléen>"
                    continue
                }
                val decoded = decodeFdtValue(bytes)
                propMap[prop] = decoded
                if (prop == "compatible") compatible = decoded
            }
            if (propMap.isNotEmpty()) {
                val dtsi = buildPseudoDtsi(dir, propMap)
                nodes.add(
                    DeviceTreeNode(
                        nodePath = dir,
                        compatible = compatible,
                        properties = propMap,
                        pseudoDtsi = dtsi
                    )
                )
            }
        }
        return nodes
    }

    private fun buildPseudoDtsi(nodePath: String, props: Map<String, String>): String {
        val nodeName = nodePath.substringAfterLast('/').ifBlank { "dt_node" }
        val sb = StringBuilder()
        sb.appendLine("// Source reconstruit depuis $nodePath")
        sb.appendLine("$nodeName {")
        props.forEach { (k, v) ->
            when {
                v == "<booléen>" -> sb.appendLine("    $k;")
                v.startsWith("0x") -> sb.appendLine("    $k = <$v>;")
                else -> sb.appendLine("    $k = \"$v\";")
            }
        }
        sb.appendLine("};")
        return sb.toString()
    }

    suspend fun probeSysfsAndDev(dynamicKeywords: Set<String>): List<SysfsDiscoveredNode> {
        val extraTokens = dynamicKeywords
            .map { it.lowercase().replace(Regex("[^a-z0-9_.-]"), "") }
            .filter { it.length >= 4 }
            .take(18)
        val tokens = (listOf(
            "finger", "fod", "udfps", "goodix", "fpc", "silead", "egistec",
            "hbm", "lhbm", "disp_param", "doze", "dim", "touch", "input",
            "drm", "backlight", "panel", "biometric", "xiaomi", "oplus", "sec"
        ) + extraTokens).distinct()

        val grepExpr = tokens.joinToString("|") { Regex.escape(it) }
        val cmd = """
            for root in /sys/class /sys/devices/platform /sys/devices/virtual /sys/bus/spi/devices /sys/bus/i2c/devices /dev; do
              if [ -e "${'$'}root" ]; then
                find "${'$'}root" -maxdepth 5 2>/dev/null | grep -iE '$grepExpr' | head -n 85
              fi
            done
        """.trimIndent()

        val res = shell.exec(cmd, preferRoot = true, timeoutMs = 16_000L)
        val candidatePaths = res.stdout.lines().map { it.trim() }.filter { it.startsWith("/") }.distinct().take(180)

        val discovered = mutableListOf<SysfsDiscoveredNode>()
        for (path in candidatePaths) {
            if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) continue

            val statLine = shell.exec("ls -ldZ ${RootShellExecutor.shellQuote(path)} 2>/dev/null", preferRoot = true, timeoutMs = 3_000L)
                .stdout.trim()
            val (perms, selinux) = parseLsZ(statLine)

            val valueStr = if (!path.startsWith("/dev/")) {
                val valRes = shell.exec(
                    "if [ -f ${RootShellExecutor.shellQuote(path)} ] && [ -r ${RootShellExecutor.shellQuote(path)} ]; then head -c 512 ${RootShellExecutor.shellQuote(path)} 2>/dev/null | tr '\\0' ' '; fi",
                    preferRoot = true,
                    timeoutMs = 2_500L
                )
                valRes.stdout.trim().take(280)
            } else {
                "<nœud périphérique caractère/bloc>"
            }

            val lower = path.lowercase()
            val category = when {
                lower.contains("hbm") || lower.contains("lhbm") || lower.contains("drm") ||
                    lower.contains("backlight") || lower.contains("panel") || lower.contains("disp") -> "AFFICHAGE"
                lower.contains("touch") || lower.contains("input") || lower.contains("fts") ||
                    lower.contains("gt9") || lower.contains("synaptics") || lower.contains("novatek") -> "TACTILE"
                else -> "BIOMETRIE_NOYAU"
            }

            discovered.add(
                SysfsDiscoveredNode(
                    path = path,
                    category = category,
                    permissions = perms,
                    seLinuxContext = selinux,
                    readableValue = valueStr
                )
            )
        }
        return discovered
    }

    private fun decodeFdtValue(bytes: ByteArray): String {
        val looksLikeStrings = bytes.lastOrNull() == 0.toByte() &&
            bytes.count { it in 32..126 || it == 0.toByte() } >= (bytes.size * 0.85)
        if (looksLikeStrings) {
            val parts = bytes.toString(Charsets.UTF_8)
                .split('\u0000')
                .filter { it.isNotBlank() }
            if (parts.isNotEmpty()) return parts.joinToString(", ")
        }
        if (bytes.size % 4 == 0 && bytes.size <= 32) {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val ints = mutableListOf<String>()
            for (i in 0 until bytes.size / 4) {
                val v = buf.getInt(i * 4)
                ints.add("0x${(v.toLong() and 0xFFFFFFFFL).toString(16)}")
            }
            return ints.joinToString(" ")
        }
        return "binaire(${bytes.size} octets): " + bytes.take(16).joinToString(" ") { "%02x".format(it) }
    }

    companion object {
        fun parseLsZ(lsLine: String): Pair<String, String> {
            if (lsLine.isBlank()) return "?" to "?"
            val tokens = lsLine.trim().split(Regex("\\s+"))
            val perms = tokens.firstOrNull().orEmpty().ifBlank { "?" }
            val seLinux = tokens.firstOrNull { it.contains(":object_r:") || it.contains("u:object_r:") } ?: "?"
            return perms to seLinux
        }
    }
}
