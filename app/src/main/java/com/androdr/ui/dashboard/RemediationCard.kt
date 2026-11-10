package com.androdr.ui.dashboard

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.network.DnsVpnService
import com.androdr.remediation.CleanReport
import com.androdr.remediation.ImplantFinding
import com.androdr.remediation.SpywareCleaner
import com.androdr.ui.theme.androdrColors

@Suppress("LongMethod")
@Composable
fun RemediationCard(
    viewModel: DashboardRemediationViewModel,
    scanThreatPackages: Set<String>,
) {
    val context = LocalContext.current
    val colors = MaterialTheme.androdrColors
    val liveImplants by viewModel.liveImplants.collectAsStateWithLifecycle()
    val isCleaning by viewModel.isCleaning.collectAsStateWithLifecycle()
    val lastReport by viewModel.lastCleanReport.collectAsStateWithLifecycle()
    val vpnActive by viewModel.vpnActive.collectAsStateWithLifecycle()

    val allThreatPackages = scanThreatPackages + liveImplants.map { it.packageName }
    val hasThreats = allThreatPackages.isNotEmpty()

    val vpnLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startDnsService(context)
        }
    }

    LaunchedEffect(lastReport) {
        if (lastReport?.needsVpnConsent == true) {
            val prepareIntent = try {
                VpnService.prepare(context)
            } catch (ignored: Exception) {
                null
            }
            if (prepareIntent != null) {
                vpnLauncher.launch(prepareIntent)
            }
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (hasThreats) {
                colors.critical.copy(alpha = 0.08f)
            } else {
                MaterialTheme.colorScheme.surfaceContainer
            }
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            RemediationHeader(hasThreats = hasThreats, threatCount = allThreatPackages.size)

            if (liveImplants.isNotEmpty()) {
                ImplantFindingsList(findings = liveImplants)
            }

            Button(
                onClick = { viewModel.cleanThreats(scanThreatPackages) },
                enabled = !isCleaning,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (hasThreats) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.primary
                    }
                )
            ) {
                if (isCleaning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.remediation_cleaning))
                } else {
                    Icon(
                        imageVector = Icons.Filled.CleaningServices,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.remediation_clean_cta))
                }
            }

            lastReport?.let { report ->
                CleanReportSection(
                    report = report,
                    onUninstall = { pkg ->
                        safeStartActivity(context, viewModel.buildUninstallIntent(pkg))
                    },
                    onOpenAppDetails = { pkg ->
                        safeStartActivity(context, viewModel.buildAppDetailsIntent(pkg))
                    }
                )
            }

            SinkholeStatusButton(
                vpnActive = vpnActive,
                onEnable = {
                    viewModel.armSinkholeSettings()
                    val prepareIntent = try {
                        VpnService.prepare(context)
                    } catch (ignored: Exception) {
                        null
                    }
                    if (prepareIntent != null) {
                        vpnLauncher.launch(prepareIntent)
                    } else {
                        startDnsService(context)
                    }
                }
            )

            HorizontalDivider()

            HardeningQuickActions(onHardening = viewModel::openHardening)
        }
    }
}

@Composable
private fun RemediationHeader(hasThreats: Boolean, threatCount: Int) {
    val colors = MaterialTheme.androdrColors
    val accent = if (hasThreats) colors.critical else MaterialTheme.colorScheme.primary
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Icon(
            imageVector = if (hasThreats) Icons.Filled.Warning else Icons.Filled.GppGood,
            contentDescription = null,
            tint = accent,
            modifier = Modifier.size(26.dp)
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.remediation_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = if (hasThreats) {
                    stringResource(R.string.remediation_subtitle_threats, threatCount)
                } else {
                    stringResource(R.string.remediation_subtitle_clean)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ImplantFindingsList(findings: List<ImplantFinding>) {
    val colors = MaterialTheme.androdrColors
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        findings.forEach { item ->
            val sevColor = when (item.severity.uppercase()) {
                "CRITICAL" -> colors.critical
                "HIGH" -> colors.high
                else -> colors.medium
            }
            Surface(
                shape = MaterialTheme.shapes.small,
                color = sevColor.copy(alpha = 0.12f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(10.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "${item.family} · ${item.appLabel}",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = sevColor
                        )
                        Text(
                            text = item.severity,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = sevColor
                        )
                    }
                    Text(
                        text = item.packageName,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = item.reason,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun CleanReportSection(
    report: CleanReport,
    onUninstall: (String) -> Unit,
    onOpenAppDetails: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(
                R.string.remediation_report_summary,
                report.killedProcesses.size,
                report.deletedArtifacts.size
            ),
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary
        )
        if (report.rootUsed) {
            Text(
                text = stringResource(
                    R.string.remediation_root_summary,
                    report.rootUninstalledPackages.size,
                    report.rootRevokedPackages.size
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary
            )
        }
        report.uninstallableUserPackages.forEach { pkg ->
            Button(
                onClick = { onUninstall(pkg) },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(stringResource(R.string.remediation_uninstall_pkg, pkg))
            }
        }
        report.systemPreloadPackages.forEach { pkg ->
            OutlinedButton(
                onClick = { onOpenAppDetails(pkg) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.remediation_disable_preload, pkg))
            }
        }
    }
}

@Composable
private fun SinkholeStatusButton(vpnActive: Boolean, onEnable: () -> Unit) {
    if (vpnActive) {
        Surface(
            shape = MaterialTheme.shapes.small,
            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.14f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Text(
                    text = stringResource(R.string.remediation_sinkhole_active),
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }
    } else {
        FilledTonalButton(
            onClick = onEnable,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(
                imageVector = Icons.Filled.Lock,
                contentDescription = null,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.remediation_sinkhole_enable))
        }
    }
}

@Composable
private fun HardeningQuickActions(
    onHardening: (SpywareCleaner.HardeningTarget) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.remediation_hardening_title),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = { onHardening(SpywareCleaner.HardeningTarget.DEVELOPER_DEBUGGING) },
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = stringResource(R.string.remediation_harden_adb),
                    style = MaterialTheme.typography.labelSmall
                )
            }
            OutlinedButton(
                onClick = { onHardening(SpywareCleaner.HardeningTarget.ACCESSIBILITY_SERVICES) },
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = stringResource(R.string.remediation_harden_accessibility),
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = { onHardening(SpywareCleaner.HardeningTarget.DEVICE_ADMINS) },
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = stringResource(R.string.remediation_harden_admins),
                    style = MaterialTheme.typography.labelSmall
                )
            }
            OutlinedButton(
                onClick = { onHardening(SpywareCleaner.HardeningTarget.ADS_PRIVACY) },
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = stringResource(R.string.remediation_harden_ads),
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
    }
}

private fun startDnsService(context: Context) {
    try {
        val intent = Intent(context, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(context, intent)
    } catch (ignored: Exception) {
        // Ignored if OS restricts foreground start while backgrounded
    }
}

private fun safeStartActivity(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (ignored: Exception) {
        // Ignored if target package was already removed
    }
}
