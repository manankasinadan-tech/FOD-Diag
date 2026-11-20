package com.example.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class ShellResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val usedRoot: Boolean
) {
    val isSuccess: Boolean get() = exitCode == 0
}

data class RootDetectionInfo(
    val isGranted: Boolean,
    val provider: String,
    val detail: String
)

object BiometricPrivacyGuard {
    private val blockedPatterns = listOf(
        Regex(".*/fpdata(/.*)?$", RegexOption.IGNORE_CASE),
        Regex(".*/data/vendor_de/.*/fingerprint.*", RegexOption.IGNORE_CASE),
        Regex(".*/data/system/users/.*/fpdata.*", RegexOption.IGNORE_CASE),
        Regex(".*/data/vendor/tee(/.*)?$", RegexOption.IGNORE_CASE),
        Regex(".*/persist/data(/.*)?$", RegexOption.IGNORE_CASE),
        Regex(".*/mnt/vendor/persist/(goodix|fpc|silead|biometrics)(/.*)?$", RegexOption.IGNORE_CASE),
        Regex(".*/keystore(/.*)?$", RegexOption.IGNORE_CASE),
        Regex(".*/gatekeeper.*", RegexOption.IGNORE_CASE),
        Regex(".*\\.fptemplate$", RegexOption.IGNORE_CASE),
        Regex(".*_calib.*\\.bin$", RegexOption.IGNORE_CASE)
    )

    fun isProtectedBiometricPath(path: String): Boolean {
        return blockedPatterns.any { it.matches(path) }
    }

    fun explainExclusion(path: String): String {
        return "Exclu par politique de sécurité biométrique (aucune lecture du contenu) : $path"
    }
}

class RootShellExecutor {

    @Volatile
    private var cachedRootGranted: Boolean? = null

    @Volatile
    private var resolvedSuBinary: String = "su"

    private val suCandidates = listOf(
        "su",
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/debug_ramdisk/su",
        "/vendor/bin/su",
        "/data/adb/ksu/bin/su",
        "/data/adb/ap/bin/su"
    )

    suspend fun detectRoot(forceRecheck: Boolean = false): RootDetectionInfo = withContext(Dispatchers.IO) {
        if (!forceRecheck && cachedRootGranted == true) {
            val quickCheck = runSuCommand("id", resolvedSuBinary, 4_000L)
            if (quickCheck.stdout.contains("uid=0")) {
                return@withContext buildRootInfo(true, resolvedSuBinary, quickCheck.stdout, quickCheck.stderr)
            }
        }

        var chosenResult: ShellResult? = null
        var chosenBin = "su"
        val checkTimeout = if (forceRecheck) 20_000L else 10_000L

        // 1. Tester 'su -c id' sur chaque binaire SU candidat (sans File.exists() car SELinux peut bloquer stat() sur /debug_ramdisk)
        for (candidate in suCandidates) {
            val idRes = runSuCommand("id", candidate, timeoutMs = checkTimeout)
            if (idRes.stdout.contains("uid=0")) {
                chosenResult = idRes
                chosenBin = candidate
                break
            }
            if (chosenResult == null && (idRes.stderr.isNotBlank() || idRes.exitCode != -2)) {
                chosenResult = idRes
            }
        }

        // 2. Fallback via 'sh -c "su -c id"' puis stdin interactif si 'su -c' était bloqué
        if (chosenResult?.stdout?.contains("uid=0") != true) {
            val shSuRes = runRaw("su -c id", useRoot = false, timeoutMs = checkTimeout)
            if (shSuRes.stdout.contains("uid=0")) {
                chosenResult = shSuRes
                chosenBin = "su"
            }
        }

        if (chosenResult?.stdout?.contains("uid=0") != true) {
            for (candidate in suCandidates) {
                val stdinRes = runSuViaStdin("id\nexit\n", candidate, timeoutMs = 8_000L)
                if (stdinRes.stdout.contains("uid=0")) {
                    chosenResult = stdinRes
                    chosenBin = candidate
                    break
                }
            }
        }

        val granted = chosenResult?.stdout?.contains("uid=0") == true
        cachedRootGranted = granted
        if (granted) {
            resolvedSuBinary = chosenBin
        }

        val metaInfo = if (granted) {
            val verRes = runSuCommand(
                "magisk -v 2>/dev/null || true; magisk -V 2>/dev/null || true; su -v 2>/dev/null || true; ksud -V 2>/dev/null || true; apd -V 2>/dev/null || true",
                chosenBin,
                timeoutMs = 4_000L
            )
            (chosenResult?.stdout.orEmpty() + "\n" + verRes.stdout)
        } else {
            chosenResult?.stdout.orEmpty()
        }

        buildRootInfo(granted, chosenBin, metaInfo, chosenResult?.stderr.orEmpty())
    }

    private fun buildRootInfo(
        granted: Boolean,
        suBin: String,
        stdout: String,
        stderr: String
    ): RootDetectionInfo {
        val combined = "$stdout\n$stderr"
        val provider = when {
            !granted -> "Aucun accès Root"
            combined.contains("MAGISK", ignoreCase = true) || combined.contains("/magisk") || File("/data/adb/magisk").exists() -> {
                val ver = stdout.lines().firstOrNull {
                    it.contains("MAGISK", ignoreCase = true) || it.matches(Regex("^[0-9]+\\.[0-9]+.*"))
                }?.trim()
                if (!ver.isNullOrBlank()) "Magisk ($ver)" else "Magisk SU"
            }
            combined.contains("ksud", ignoreCase = true) || combined.contains("KernelSU", ignoreCase = true) -> "KernelSU"
            combined.contains("apd", ignoreCase = true) || combined.contains("APatch", ignoreCase = true) -> "APatch"
            else -> "SU ($suBin, uid=0)"
        }

        val detail = if (granted) {
            val uidLine = stdout.lines().firstOrNull { it.contains("uid=0") }?.trim().orEmpty()
            "Accès superutilisateur actif ($provider) — $uidLine"
        } else {
            val err = stderr.trim().ifBlank { "Permission su refusée ou binaire su introuvable" }
            "Mode non-root : $err"
        }
        return RootDetectionInfo(isGranted = granted, provider = provider, detail = detail)
    }

    suspend fun exec(
        command: String,
        preferRoot: Boolean = true,
        timeoutMs: Long = 14_000L
    ): ShellResult = withContext(Dispatchers.IO) {
        val tryRoot = preferRoot && (cachedRootGranted != false)
        if (tryRoot) {
            val res = runSuCommand(command, resolvedSuBinary, timeoutMs)
            if (res.isSuccess || res.stdout.isNotBlank()) {
                return@withContext res
            }
        }
        runRaw(command, useRoot = false, timeoutMs = timeoutMs)
    }

    fun startStreamingProcess(
        command: String,
        preferRoot: Boolean = true
    ): Process? {
        val useRoot = preferRoot && (cachedRootGranted != false)
        return runCatching {
            if (useRoot) {
                ProcessBuilder(resolvedSuBinary, "-c", command).redirectErrorStream(true).start()
            } else {
                ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start()
            }
        }.getOrNull()
    }

    suspend fun readFileBytesSafe(
        path: String,
        maxBytes: Int = 24 * 1024 * 1024,
        preferRoot: Boolean = true
    ): ByteArray? = withContext(Dispatchers.IO) {
        if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) {
            return@withContext null
        }

        val directFile = File(path)
        if (directFile.exists() && directFile.isFile && directFile.canRead()) {
            return@withContext runCatching {
                directFile.inputStream().use { input -> readUpTo(input, maxBytes) }
            }.getOrNull()
        }

        if (!preferRoot || cachedRootGranted == false) return@withContext null

        val escaped = shellQuote(path)
        val cmd = "head -c $maxBytes $escaped 2>/dev/null || cat $escaped 2>/dev/null"
        runCatching {
            val process = ProcessBuilder(resolvedSuBinary, "-c", cmd).start()
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(16384)
            process.inputStream.use { stream ->
                var total = 0
                while (total < maxBytes) {
                    val read = stream.read(buffer, 0, minOf(buffer.size, maxBytes - total))
                    if (read <= 0) break
                    out.write(buffer, 0, read)
                    total += read
                }
            }
            val finished = process.waitFor(12, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return@runCatching null
            }
            val bytes = out.toByteArray()
            if (bytes.isEmpty() && process.exitValue() != 0) null else bytes
        }.getOrNull()
    }

    suspend fun copyFileToDestinationSafe(
        sourcePath: String,
        destFile: File,
        maxBytes: Long = 24L * 1024L * 1024L
    ): Boolean = withContext(Dispatchers.IO) {
        if (BiometricPrivacyGuard.isProtectedBiometricPath(sourcePath)) return@withContext false
        val bytes = readFileBytesSafe(sourcePath, maxBytes = maxBytes.toInt(), preferRoot = true) ?: return@withContext false
        if (bytes.isEmpty()) return@withContext false
        runCatching {
            destFile.parentFile?.mkdirs()
            destFile.writeBytes(bytes)
            true
        }.getOrDefault(false)
    }

    suspend fun computeSha256Safe(path: String, preferRoot: Boolean = true): String = withContext(Dispatchers.IO) {
        if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) {
            return@withContext "EXCLU_PROTECTION_BIOMETRIQUE"
        }
        val directFile = File(path)
        if (directFile.exists() && directFile.isFile && directFile.canRead()) {
            val digest = runCatching {
                val md = MessageDigest.getInstance("SHA-256")
                directFile.inputStream().use { input ->
                    val buf = ByteArray(16384)
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        md.update(buf, 0, n)
                    }
                }
                md.digest().joinToString("") { "%02x".format(it) }
            }.getOrNull()
            if (digest != null) return@withContext digest
        }

        if (preferRoot && cachedRootGranted != false) {
            val res = exec("sha256sum ${shellQuote(path)} 2>/dev/null | awk '{print \$1}'", preferRoot = true, timeoutMs = 8_000L)
            val hash = res.stdout.trim().lines().firstOrNull()?.trim().orEmpty()
            if (hash.length == 64 && hash.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                return@withContext hash.lowercase()
            }
        }
        "INDISPONIBLE"
    }

    private fun readUpTo(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16384)
        var total = 0
        while (total < maxBytes) {
            val n = input.read(buf, 0, minOf(buf.size, maxBytes - total))
            if (n <= 0) break
            out.write(buf, 0, n)
            total += n
        }
        return out.toByteArray()
    }

    private fun runSuCommand(command: String, suBinary: String, timeoutMs: Long): ShellResult {
        return runProcess(ProcessBuilder(suBinary, "-c", command), command, useRoot = true, timeoutMs = timeoutMs)
    }

    private fun runSuViaStdin(script: String, suBinary: String, timeoutMs: Long): ShellResult {
        return try {
            val process = ProcessBuilder(suBinary).start()
            process.outputStream.bufferedWriter().use { w ->
                w.write(script)
                w.flush()
            }
            collectProcessResult(process, script, useRoot = true, timeoutMs = timeoutMs)
        } catch (e: Exception) {
            ShellResult(-2, "", e.localizedMessage ?: "Erreur stdin su", usedRoot = true)
        }
    }

    private fun runRaw(command: String, useRoot: Boolean, timeoutMs: Long): ShellResult {
        val pb = if (useRoot) ProcessBuilder(resolvedSuBinary, "-c", command) else ProcessBuilder("sh", "-c", command)
        return runProcess(pb, command, useRoot, timeoutMs)
    }

    private fun runProcess(pb: ProcessBuilder, label: String, useRoot: Boolean, timeoutMs: Long): ShellResult {
        return try {
            val process = pb.start()
            collectProcessResult(process, label, useRoot, timeoutMs)
        } catch (e: Exception) {
            ShellResult(
                exitCode = -2,
                stdout = "",
                stderr = e.localizedMessage ?: "Erreur d'exécution shell",
                usedRoot = useRoot
            )
        }
    }

    private fun collectProcessResult(
        process: Process,
        label: String,
        useRoot: Boolean,
        timeoutMs: Long
    ): ShellResult {
        val stdoutBuf = StringBuilder()
        val stderrBuf = StringBuilder()

        val tOut = Thread {
            runCatching {
                process.inputStream.bufferedReader().use { r ->
                    val c = CharArray(4096)
                    while (true) {
                        val n = r.read(c)
                        if (n <= 0) break
                        if (stdoutBuf.length < 3_500_000) stdoutBuf.append(c, 0, n)
                    }
                }
            }
        }
        val tErr = Thread {
            runCatching {
                process.errorStream.bufferedReader().use { r ->
                    val c = CharArray(4096)
                    while (true) {
                        val n = r.read(c)
                        if (n <= 0) break
                        if (stderrBuf.length < 200_000) stderrBuf.append(c, 0, n)
                    }
                }
            }
        }
        tOut.start()
        tErr.start()

        val done = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!done) {
            process.destroyForcibly()
            tOut.join(300)
            tErr.join(300)
            return ShellResult(-1, stdoutBuf.toString(), "Délai dépassé (${timeoutMs}ms) : $label", useRoot)
        }
        tOut.join(1000)
        tErr.join(1000)
        return ShellResult(process.exitValue(), stdoutBuf.toString(), stderrBuf.toString(), useRoot)
    }

    companion object {
        fun shellQuote(value: String): String {
            return "'" + value.replace("'", "'\\''") + "'"
        }
    }
}
