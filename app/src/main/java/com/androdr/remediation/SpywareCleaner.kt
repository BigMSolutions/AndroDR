package com.androdr.remediation

import android.Manifest
import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Environment
import android.provider.Settings
import android.util.Log
import androidx.core.content.ContextCompat
import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.KnownSpywareArtifactsResolver
import com.androdr.network.DnsVpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Live heuristic implant / covert-preload finding surfaced by [SpywareCleaner.inspectLiveImplants]
 * so high-priority 2026 threats (disguised Go native RAT binaries, NFC ghost-tap combos,
 * VPN-blinding Accessibility trojans, and silent carrier preload installers) can be
 * neutralized immediately from the Active Remediation console.
 */
data class ImplantFinding(
    val packageName: String,
    val appLabel: String,
    val family: String,
    val severity: String,
    val reason: String,
    val isSystemApp: Boolean,
)

/**
 * Result of executing [SpywareCleaner.cleanAndNeutralize].
 */
data class CleanReport(
    val killedProcesses: List<String>,
    val deletedArtifacts: List<String>,
    val rootUninstalledPackages: List<String>,
    val rootRevokedPackages: List<String>,
    val uninstallableUserPackages: List<String>,
    val systemPreloadPackages: List<String>,
    val sinkholeConfigured: Boolean,
    val vpnActive: Boolean,
    val needsVpnConsent: Boolean,
    val rootUsed: Boolean,
) {
    val totalActionsCount: Int
        get() = killedProcesses.size +
            deletedArtifacts.size +
            rootUninstalledPackages.size +
            rootRevokedPackages.size +
            (if (sinkholeConfigured) 1 else 0)
}

/**
 * Multi-stage on-device Active Spyware & Malware Remediation Engine.
 *
 * Works across both standard unrooted Android devices (process termination, shared-storage
 * dropper/artifact purge, local DNS C2 sinkhole activation, native `ACTION_DELETE` uninstall
 * orchestration, and one-tap system hardening intents) and rooted/enterprise devices
 * (`su` force-stop, `appops` revocation, `pm uninstall --user 0`, `/data/local/tmp` RAT daemon
 * termination, and Wireless/USB ADB lockdown).
 */
@Singleton
class SpywareCleaner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val settingsRepository: SettingsRepository,
    private val knownSpywareArtifactsResolver: KnownSpywareArtifactsResolver,
) {

    /**
     * Scans installed packages for high-confidence 2026 implant & covert-installer patterns:
     * 1. **RatHat** disguised Go native binaries (`liblocal-service.so` + `libmedia_codec.so`).
     * 2. **WindRelay + SpyNote** NFC contactless relay + `DUMP` permission combo on non-system apps.
     * 3. **RemControl / ToxicPanda 2.0 / Mirax** sideloaded apps combining `BIND_VPN_SERVICE`
     *    (used to blind Play Protect) with `BIND_ACCESSIBILITY_SERVICE`.
     * 4. **Covert Carrier/OEM Preload Installers** (`com.ironsource.appcloud.oobe*`, `com.aura.oobe.*`,
     *    `com.dti.att`, `com.dti.folderlauncher`) capable of silent background app installation.
     */
    suspend fun inspectLiveImplants(): List<ImplantFinding> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages = try {
            pm.getInstalledPackages(
                PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
            )
        } catch (ignored: Exception) {
            emptyList()
        }
        packages.mapNotNull { pkg -> evaluatePackageImplant(pm, pkg) }
    }

    @Suppress("ReturnCount", "LongMethod")
    internal fun evaluatePackageImplant(pm: PackageManager, pkg: PackageInfo): ImplantFinding? {
        val packageName = pkg.packageName ?: return null
        if (packageName == context.packageName || packageName.startsWith("com.androdr")) return null
        val appInfo = pkg.applicationInfo ?: return null
        val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val label = try {
            pm.getApplicationLabel(appInfo).toString()
        } catch (ignored: Exception) {
            packageName
        }

        val nativeLibs = extractNativeLibs(appInfo)
        if ("liblocal-service.so" in nativeLibs ||
            ("libmedia_codec.so" in nativeLibs && !isSystemApp)
        ) {
            val matchedLibs = nativeLibs.intersect(RATHAT_NATIVE_LIBS).joinToString()
            return ImplantFinding(
                packageName = packageName,
                appLabel = label,
                family = "RatHat RAT",
                severity = "CRITICAL",
                reason = "Disguised Go reverse-proxy / ADB self-pairing implant binary ($matchedLibs)",
                isSystemApp = isSystemApp,
            )
        }

        val perms = pkg.requestedPermissions?.toSet().orEmpty()
        if (!isSystemApp && Manifest.permission.NFC in perms && "android.permission.DUMP" in perms) {
            return ImplantFinding(
                packageName = packageName,
                appLabel = label,
                family = "WindRelay NFC Malware",
                severity = "CRITICAL",
                reason = "Non-system app requesting both NFC contactless reader access and system DUMP inspection",
                isSystemApp = false,
            )
        }

        val servicePerms = pkg.services?.mapNotNull { it.permission }?.toSet().orEmpty()
        if (!isSystemApp &&
            "android.permission.BIND_VPN_SERVICE" in servicePerms &&
            "android.permission.BIND_ACCESSIBILITY_SERVICE" in servicePerms
        ) {
            return ImplantFinding(
                packageName = packageName,
                appLabel = label,
                family = "RemControl / ToxicPanda DTO",
                severity = "HIGH",
                reason = "Combines Accessibility device control with local VPN service (used to blind Play Protect)",
                isSystemApp = false,
            )
        }

        if (PRELOAD_INSTALLER_PREFIXES.any { packageName.startsWith(it) }) {
            return ImplantFinding(
                packageName = packageName,
                appLabel = label,
                family = "Silent Preload Installer",
                severity = "MEDIUM",
                reason = "Covert carrier/OEM setup agent capable of installing packages without Play Store consent",
                isSystemApp = isSystemApp,
            )
        }

        return null
    }

    /**
     * Executes the 5-stage active spyware & malware remediation pipeline.
     */
    suspend fun cleanAndNeutralize(packagesToClean: Set<String>): CleanReport = withContext(Dispatchers.IO) {
        val sanitizedPackages = packagesToClean
            .map { it.trim() }
            .filter { it.isNotEmpty() && SAFE_PACKAGE_REGEX.matches(it) && !it.startsWith("com.androdr") }
            .toSet()

        // Stage 1: Kill active background processes
        val killed = killBackgroundProcesses(sanitizedPackages)

        // Stage 2: Purge accessible spyware/dropper staging artifacts
        val deletedArtifacts = purgeSpywareArtifacts()

        // Stage 3: Attempt privileged root/shell eradication if su is available
        val rootResult = attemptRootDeepClean(sanitizedPackages)

        // Stage 4: Enable C2 & Threat-Intel DNS Sinkhole
        settingsRepository.setBlocklistBlockMode(true)
        settingsRepository.setDomainIocBlockMode(true)
        val (vpnStarted, needsConsent) = activateVpnSinkholeIfPermitted()

        // Stage 5: Partition remaining installed packages into user-uninstallable vs system-preload
        val pm = context.packageManager
        val remainingUser = mutableListOf<String>()
        val remainingSystem = mutableListOf<String>()
        for (pkg in sanitizedPackages - rootResult.uninstalled.toSet()) {
            val appInfo = try {
                pm.getApplicationInfo(pkg, 0)
            } catch (ignored: Exception) {
                null
            }
            if (appInfo != null) {
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                if (isSystem && !isUpdatedSystem) {
                    remainingSystem += pkg
                } else {
                    remainingUser += pkg
                }
            }
        }

        CleanReport(
            killedProcesses = killed,
            deletedArtifacts = (deletedArtifacts + rootResult.deletedRootArtifacts).distinct(),
            rootUninstalledPackages = rootResult.uninstalled,
            rootRevokedPackages = rootResult.revoked,
            uninstallableUserPackages = remainingUser,
            systemPreloadPackages = remainingSystem,
            sinkholeConfigured = true,
            vpnActive = vpnStarted || DnsVpnService.isRunning.value,
            needsVpnConsent = needsConsent,
            rootUsed = rootResult.rootAvailable,
        )
    }

    private fun killBackgroundProcesses(packages: Set<String>): List<String> {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return emptyList()
        val terminated = mutableListOf<String>()
        for (pkg in packages) {
            try {
                am.killBackgroundProcesses(pkg)
                terminated += pkg
            } catch (ignored: Exception) {
                Log.w(TAG, "Failed to kill background process for $pkg")
            }
        }
        return terminated
    }

    private fun purgeSpywareArtifacts(): List<String> {
        val candidatePaths = LinkedHashSet<String>()
        candidatePaths.addAll(knownSpywareArtifactsResolver.paths)
        @Suppress("DEPRECATION")
        val extRoot = try {
            Environment.getExternalStorageDirectory()?.absolutePath
        } catch (ignored: Exception) {
            null
        }
        if (!extRoot.isNullOrBlank()) {
            EXTRA_DROPPER_RELATIVE_PATHS.forEach { rel ->
                candidatePaths += "$extRoot/$rel"
            }
        }

        val removed = mutableListOf<String>()
        for (path in candidatePaths) {
            try {
                val file = File(path)
                if (file.exists() && deleteRecursivelySafe(file)) {
                    removed += path
                }
            } catch (ignored: Exception) {
                // Restricted paths (/data/local/tmp) require Stage 3 root shell on SELinux-enforcing builds.
            }
        }
        return removed
    }

    private fun deleteRecursivelySafe(target: File): Boolean {
        val canonical = try {
            target.canonicalPath
        } catch (ignored: Exception) {
            return false
        }
        // Guardrail: only ever delete inside /data/local/tmp or external storage.
        val allowedPrefix = canonical.startsWith("/data/local/tmp/") ||
            canonical.startsWith("/storage/") ||
            canonical.startsWith("/sdcard/")
        return allowedPrefix && target.deleteRecursively()
    }

    private data class RootCleanResult(
        val rootAvailable: Boolean,
        val uninstalled: List<String>,
        val revoked: List<String>,
        val deletedRootArtifacts: List<String>,
    )

    private fun attemptRootDeepClean(packages: Set<String>): RootCleanResult {
        if (!isRootAvailable()) {
            return RootCleanResult(false, emptyList(), emptyList(), emptyList())
        }

        // Neutralize RatHat / ADB self-pairing daemons & Wireless/USB ADB exposure
        val globalHardeningCmds = listOf(
            "pkill -9 -f '/data/local/tmp/frpc' 2>/dev/null || true",
            "pkill -9 -f '/data/local/tmp/local-service' 2>/dev/null || true",
            "settings put global adb_wifi_enabled 0 2>/dev/null || true",
            "settings put global adb_enabled 0 2>/dev/null || true",
        )
        runSuScript(globalHardeningCmds.joinToString("; "))

        val deletedTmp = mutableListOf<String>()
        for (tmpArtifact in ROOT_TMP_ARTIFACTS) {
            val checkAndRm = "if [ -e '$tmpArtifact' ]; then rm -rf '$tmpArtifact' && echo REMOVED; fi"
            val out = runSuScript(checkAndRm)
            if (out.contains("REMOVED")) {
                deletedTmp += tmpArtifact
            }
        }

        val uninstalled = mutableListOf<String>()
        val revoked = mutableListOf<String>()

        for (pkg in packages) {
            if (!SAFE_PACKAGE_REGEX.matches(pkg)) continue
            val revokeScript = buildString {
                append("am force-stop ").append(pkg).append("; ")
                for (op in DANGEROUS_APPOPS) {
                    append("appops set ").append(pkg).append(' ').append(op).append(" ignore 2>/dev/null; ")
                }
                append("echo REVOKED")
            }
            if (runSuScript(revokeScript).contains("REVOKED")) {
                revoked += pkg
            }

            val uninstallOut = runSuScript(
                "pm uninstall --user 0 $pkg 2>/dev/null || pm disable-user --user 0 $pkg 2>/dev/null"
            )
            if (uninstallOut.contains("Success", ignoreCase = true) ||
                uninstallOut.contains("disabled-user", ignoreCase = true)
            ) {
                uninstalled += pkg
            }
        }

        return RootCleanResult(
            rootAvailable = true,
            uninstalled = uninstalled,
            revoked = revoked,
            deletedRootArtifacts = deletedTmp,
        )
    }

    private fun isRootAvailable(): Boolean {
        val suLocations = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/debug_ramdisk/su", "/su/bin/su")
        if (suLocations.none { File(it).exists() }) return false
        return runSuScript("id").contains("uid=0")
    }

    private fun runSuScript(script: String): String {
        return try {
            val process = ProcessBuilder("su", "-c", script)
                .redirectErrorStream(true)
                .start()
            val completed = process.waitFor(SU_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                ""
            } else {
                process.inputStream.bufferedReader().use { it.readText() }
            }
        } catch (ignored: Exception) {
            ""
        }
    }

    private fun activateVpnSinkholeIfPermitted(): Pair<Boolean, Boolean> {
        return try {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                false to true
            } else {
                val startIntent = Intent(context, DnsVpnService::class.java).apply {
                    action = DnsVpnService.ACTION_START
                }
                ContextCompat.startForegroundService(context, startIntent)
                true to false
            }
        } catch (ignored: Exception) {
            false to false
        }
    }

    private fun extractNativeLibs(appInfo: ApplicationInfo): Set<String> {
        val libs = LinkedHashSet<String>()
        appInfo.nativeLibraryDir?.let { dir ->
            File(dir).listFiles()?.forEach { f ->
                if (f.name.endsWith(".so")) libs += f.name
            }
        }
        val apkPath = appInfo.publicSourceDir ?: return libs
        try {
            ZipFile(apkPath).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val name = entries.nextElement().name
                    if (name.startsWith("lib/") && name.endsWith(".so")) {
                        libs += name.substringAfterLast('/')
                    }
                }
            }
        } catch (ignored: Exception) {
            // Unreadable APK skipped safely
        }
        return libs
    }

    /** Builds a native `ACTION_DELETE` uninstall intent for a user-installed package. */
    fun buildUninstallIntent(packageName: String): Intent =
        Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName")).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

    /** Builds a system App Info intent for force-stopping or disabling preloaded packages. */
    fun buildAppDetailsIntent(packageName: String): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

    /** Opens system settings safely with a fallback to main Settings if an OEM customized the screen. */
    fun launchHardeningScreen(target: HardeningTarget) {
        val primary = when (target) {
            HardeningTarget.DEVELOPER_DEBUGGING ->
                Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
            HardeningTarget.ACCESSIBILITY_SERVICES ->
                Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            HardeningTarget.DEVICE_ADMINS ->
                Intent().setComponent(
                    ComponentName("com.android.settings", "com.android.settings.DeviceAdminSettings")
                )
            HardeningTarget.ADS_PRIVACY ->
                Intent("com.google.android.gms.settings.ADS_PRIVACY")
        }.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        val fallback = when (target) {
            HardeningTarget.DEVICE_ADMINS -> Intent(Settings.ACTION_SECURITY_SETTINGS)
            else -> Intent(Settings.ACTION_SETTINGS)
        }.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        try {
            context.startActivity(primary)
        } catch (ignored: Exception) {
            try {
                context.startActivity(fallback)
            } catch (ignoredFallback: Exception) {
                Log.w(TAG, "Unable to open settings for $target")
            }
        }
    }

    enum class HardeningTarget {
        DEVELOPER_DEBUGGING,
        ACCESSIBILITY_SERVICES,
        DEVICE_ADMINS,
        ADS_PRIVACY,
    }

    companion object {
        private const val TAG = "SpywareCleaner"
        private const val SU_TIMEOUT_SECONDS = 8L
        internal val SAFE_PACKAGE_REGEX = Regex("^[a-zA-Z0-9_]+(\\.[a-zA-Z0-9_]+)+$")

        internal val RATHAT_NATIVE_LIBS = setOf(
            "liblocal-service.so",
            "libmedia_codec.so",
        )

        internal val PRELOAD_INSTALLER_PREFIXES = listOf(
            "com.ironsource.appcloud.oobe",
            "com.aura.oobe.",
            "com.dti.att",
            "com.dti.folderlauncher",
        )

        private val EXTRA_DROPPER_RELATIVE_PATHS = listOf(
            ".hidden_config",
            "Android/data/.system_update",
            "Android/data/locateValues.json",
            "Download/GooglePlayServicesUpdate.apk",
            "Download/SystemUpdate.apk",
        )

        private val ROOT_TMP_ARTIFACTS = listOf(
            "/data/local/tmp/.raptor",
            "/data/local/tmp/.stat",
            "/data/local/tmp/.mobilesoftwareupdate",
            "/data/local/tmp/wd",
            "/data/local/tmp/dropbox",
            "/data/local/tmp/frpc",
            "/data/local/tmp/local-service",
            "/data/local/tmp/local-service.update",
            "/data/local/tmp/app.apk",
            "/data/local/tmp/cellebrite",
        )

        private val DANGEROUS_APPOPS = listOf(
            "ACCESS_RESTRICTED_SETTINGS",
            "PROJECT_MEDIA",
            "SYSTEM_ALERT_WINDOW",
            "GET_USAGE_STATS",
            "REQUEST_INSTALL_PACKAGES",
            "WRITE_SETTINGS",
            "MANAGE_EXTERNAL_STORAGE",
            "READ_SMS",
            "RECEIVE_SMS",
            "RECORD_AUDIO",
            "CAMERA",
            "FINE_LOCATION",
        )
    }
}
