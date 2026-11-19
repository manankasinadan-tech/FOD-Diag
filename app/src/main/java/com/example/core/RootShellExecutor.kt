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

    suspend fun detectRoot(forceRecheck: Boolean = false): RootDetectionInfo = withContext(Dispatchers.IO) {
        val suResult = runRaw(command = "id; su -v 2>/dev/null; which magisk ksud apd su 2>/dev/null", useRoot = true, timeoutMs = 6_000L)
        val granted = suResult.isSuccess && suResult.stdout.contains("uid=0")
        cachedRootGranted = granted

        val combined = suResult.stdout + "\n" + suResult.stderr
        val provider = when {
            combined.contains("MAGISK", ignoreCase = true) || combined.contains("/magisk") -> {
                val versionLine = suResult.stdout.lines().firstOrNull { it.contains("MAGISK", ignoreCase = true) }?.trim()
                versionLine ?: "Magisk SU"
            }
            combined.contains("ksud", ignoreCase = true) || combined.contains("KernelSU", ignoreCase = true) -> "KernelSU"
            combined.contains("apd", ignoreCase = true) || combined.contains("APatch", ignoreCase = true) -> "APatch"
            granted -> "SU (uid=0)"
            else -> "Aucun accès Root"
        }

        val detail = if (granted) {
            val uidLine = suResult.stdout.lines().firstOrNull { it.contains("uid=0") }?.trim().orEmpty()
            "Accès superutilisateur actif ($provider) — $uidLine"
        } else {
            val err = suResult.stderr.trim().ifBlank { "Permission su refusée ou binaire su absent" }
            "Mode non-root (lecture limitée aux nœuds accessibles) : $err"
        }

        RootDetectionInfo(isGranted = granted, provider = provider, detail = detail)
    }

    suspend fun exec(
        command: String,
        preferRoot: Boolean = true,
        timeoutMs: Long = 12_000L
    ): ShellResult = withContext(Dispatchers.IO) {
        val tryRoot = preferRoot && (cachedRootGranted != false)
        if (tryRoot) {
            val res = runRaw(command, useRoot = true, timeoutMs = timeoutMs)
            if (res.isSuccess || res.stdout.isNotBlank()) {
                return@withContext res
            }
        }
        runRaw(command, useRoot = false, timeoutMs = timeoutMs)
    }

    suspend fun execForceShell(command: String, useRoot: Boolean, timeoutMs: Long = 12_000L): ShellResult =
        withContext(Dispatchers.IO) {
            runRaw(command, useRoot = useRoot, timeoutMs = timeoutMs)
        }

    suspend fun readFileBytesSafe(
        path: String,
        maxBytes: Int = 18 * 1024 * 1024,
        preferRoot: Boolean = true
    ): ByteArray? = withContext(Dispatchers.IO) {
        if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) {
            return@withContext null
        }

        val directFile = File(path)
        if (directFile.exists() && directFile.isFile && directFile.canRead()) {
            return@withContext runCatching {
                directFile.inputStream().use { input ->
                    readUpTo(input, maxBytes)
                }
            }.getOrNull()
        }

        if (!preferRoot || cachedRootGranted == false) return@withContext null

        val escaped = shellQuote(path)
        val cmd = "head -c $maxBytes $escaped 2>/dev/null"
        runCatching {
            val process = ProcessBuilder("su", "-c", cmd).start()
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
            val finished = process.waitFor(10, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return@runCatching null
            }
            val bytes = out.toByteArray()
            if (bytes.isEmpty() && process.exitValue() != 0) null else bytes
        }.getOrNull()
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

    private fun runRaw(command: String, useRoot: Boolean, timeoutMs: Long): ShellResult {
        return try {
            val pb = if (useRoot) {
                ProcessBuilder("su", "-c", command)
            } else {
                ProcessBuilder("sh", "-c", command)
            }
            val process = pb.start()
            val stdoutBuf = StringBuilder()
            val stderrBuf = StringBuilder()

            val tOut = Thread {
                runCatching {
                    process.inputStream.bufferedReader().use { r ->
                        val c = CharArray(4096)
                        while (true) {
                            val n = r.read(c)
                            if (n <= 0) break
                            if (stdoutBuf.length < 2_500_000) {
                                stdoutBuf.append(c, 0, n)
                            }
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
                            if (stderrBuf.length < 200_000) {
                                stderrBuf.append(c, 0, n)
                            }
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
                return ShellResult(
                    exitCode = -1,
                    stdout = stdoutBuf.toString(),
                    stderr = "Délai dépassé (${timeoutMs}ms) : $command",
                    usedRoot = useRoot
                )
            }
            tOut.join(1000)
            tErr.join(1000)
            ShellResult(
                exitCode = process.exitValue(),
                stdout = stdoutBuf.toString(),
                stderr = stderrBuf.toString(),
                usedRoot = useRoot
            )
        } catch (e: Exception) {
            ShellResult(
                exitCode = -2,
                stdout = "",
                stderr = e.localizedMessage ?: "Erreur d'exécution shell",
                usedRoot = useRoot
            )
        }
    }

    companion object {
        fun shellQuote(value: String): String {
            return "'" + value.replace("'", "'\\''") + "'"
        }
    }
}
