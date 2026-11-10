package com.androdr.remediation

import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.KnownSpywareArtifactsResolver
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SpywareCleanerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var pm: PackageManager
    private lateinit var am: ActivityManager
    private lateinit var settingsRepository: SettingsRepository
    private lateinit var artifactsResolver: KnownSpywareArtifactsResolver
    private lateinit var cleaner: SpywareCleaner

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        pm = mockk(relaxed = true)
        am = mockk(relaxed = true)
        settingsRepository = mockk(relaxed = true)
        artifactsResolver = mockk(relaxed = true)

        every { context.packageName } returns "com.androdr"
        every { context.packageManager } returns pm
        every { context.getSystemService(Context.ACTIVITY_SERVICE) } returns am
        every { artifactsResolver.paths } returns emptyList()

        cleaner = SpywareCleaner(
            context = context,
            settingsRepository = settingsRepository,
            knownSpywareArtifactsResolver = artifactsResolver,
        )
    }

    @Test
    fun `detects RatHat disguised Go native library as CRITICAL`() {
        val libDir = tempFolder.newFolder("rathat_libs")
        File(libDir, "liblocal-service.so").writeBytes(byteArrayOf(0x7F, 0x45, 0x4C, 0x46))

        val appInfo = ApplicationInfo().apply {
            packageName = "com.fake.systemupdate"
            nativeLibraryDir = libDir.absolutePath
            flags = 0
        }
        val pkgInfo = PackageInfo().apply {
            packageName = "com.fake.systemupdate"
            applicationInfo = appInfo
        }
        every { pm.getApplicationLabel(appInfo) } returns "System Update"

        val finding = cleaner.evaluatePackageImplant(pm, pkgInfo)

        assertNotNull(finding)
        assertEquals("RatHat RAT", finding!!.family)
        assertEquals("CRITICAL", finding.severity)
        assertTrue(finding.reason.contains("liblocal-service.so"))
    }

    @Test
    fun `detects WindRelay NFC and DUMP permission combo on user apps only`() {
        val userApp = ApplicationInfo().apply {
            packageName = "com.nfc.taprelay"
            flags = 0
        }
        val userPkg = PackageInfo().apply {
            packageName = "com.nfc.taprelay"
            applicationInfo = userApp
            requestedPermissions = arrayOf(Manifest.permission.NFC, "android.permission.DUMP")
        }
        every { pm.getApplicationLabel(userApp) } returns "TapPay"

        val finding = cleaner.evaluatePackageImplant(pm, userPkg)
        assertNotNull(finding)
        assertEquals("WindRelay NFC Malware", finding!!.family)
        assertEquals("CRITICAL", finding.severity)

        val sysApp = ApplicationInfo().apply {
            packageName = "com.android.nfc"
            flags = ApplicationInfo.FLAG_SYSTEM
        }
        val sysPkg = PackageInfo().apply {
            packageName = "com.android.nfc"
            applicationInfo = sysApp
            requestedPermissions = arrayOf(Manifest.permission.NFC, "android.permission.DUMP")
        }
        assertNull(cleaner.evaluatePackageImplant(pm, sysPkg))
    }

    @Test
    fun `detects RemControl VPN plus Accessibility service combo on user apps`() {
        val appInfo = ApplicationInfo().apply {
            packageName = "net.wgrjvz.toolyt93a"
            flags = 0
        }
        val vpnSvc = ServiceInfo().apply { permission = "android.permission.BIND_VPN_SERVICE" }
        val accSvc = ServiceInfo().apply { permission = "android.permission.BIND_ACCESSIBILITY_SERVICE" }
        val pkgInfo = PackageInfo().apply {
            packageName = "net.wgrjvz.toolyt93a"
            applicationInfo = appInfo
            services = arrayOf(vpnSvc, accSvc)
        }
        every { pm.getApplicationLabel(appInfo) } returns "Security Helper"

        val finding = cleaner.evaluatePackageImplant(pm, pkgInfo)
        assertNotNull(finding)
        assertEquals("RemControl / ToxicPanda DTO", finding!!.family)
        assertEquals("HIGH", finding.severity)
    }

    @Test
    fun `flags silent OEM and carrier preload installers and ignores self or benign apps`() {
        val preloadInfo = ApplicationInfo().apply {
            packageName = "com.aura.oobe.samsung"
            flags = ApplicationInfo.FLAG_SYSTEM
        }
        val preloadPkg = PackageInfo().apply {
            packageName = "com.aura.oobe.samsung"
            applicationInfo = preloadInfo
        }
        every { pm.getApplicationLabel(preloadInfo) } returns "AppCloud Setup"

        val preloadFinding = cleaner.evaluatePackageImplant(pm, preloadPkg)
        assertNotNull(preloadFinding)
        assertEquals("Silent Preload Installer", preloadFinding!!.family)
        assertEquals("MEDIUM", preloadFinding.severity)
        assertTrue(preloadFinding.isSystemApp)

        val selfPkg = PackageInfo().apply {
            packageName = "com.androdr.debug"
            applicationInfo = ApplicationInfo().apply { packageName = "com.androdr.debug" }
        }
        assertNull(cleaner.evaluatePackageImplant(pm, selfPkg))

        val benignPkg = PackageInfo().apply {
            packageName = "org.mozilla.firefox"
            applicationInfo = ApplicationInfo().apply { packageName = "org.mozilla.firefox" }
        }
        assertNull(cleaner.evaluatePackageImplant(pm, benignPkg))
    }

    @Test
    fun `cleanAndNeutralize kills processes, arms DNS sinkhole, and filters unsafe package names`() = runTest {
        val userThreatInfo = ApplicationInfo().apply {
            packageName = "quizzical.washbowl.calamity"
            flags = 0
        }
        val sysPreloadInfo = ApplicationInfo().apply {
            packageName = "com.ironsource.appcloud.oobe"
            flags = ApplicationInfo.FLAG_SYSTEM
        }
        every { pm.getApplicationInfo("quizzical.washbowl.calamity", 0) } returns userThreatInfo
        every { pm.getApplicationInfo("com.ironsource.appcloud.oobe", 0) } returns sysPreloadInfo

        val report = cleaner.cleanAndNeutralize(
            setOf(
                "quizzical.washbowl.calamity",
                "com.ironsource.appcloud.oobe",
                "com.androdr",
                "bad;rm -rf /",
            )
        )

        verify { am.killBackgroundProcesses("quizzical.washbowl.calamity") }
        verify { am.killBackgroundProcesses("com.ironsource.appcloud.oobe") }
        verify(exactly = 0) { am.killBackgroundProcesses("com.androdr") }
        coVerify { settingsRepository.setBlocklistBlockMode(true) }
        coVerify { settingsRepository.setDomainIocBlockMode(true) }
        assertTrue(report.sinkholeConfigured)
        assertEquals(listOf("quizzical.washbowl.calamity"), report.uninstallableUserPackages)
        assertEquals(listOf("com.ironsource.appcloud.oobe"), report.systemPreloadPackages)
    }
}
