package com.androdr.ui.dashboard

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.SettingsRepository
import com.androdr.network.DnsVpnService
import com.androdr.remediation.CleanReport
import com.androdr.remediation.ImplantFinding
import com.androdr.remediation.SpywareCleaner
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ViewModel backing the Dashboard Active Threat Remediation console.
 * Kept separate from [DashboardViewModel] so existing Dashboard ViewModel unit tests
 * remain isolated while adding live implant detection and 5-stage active remediation.
 */
@HiltViewModel
class DashboardRemediationViewModel @Inject constructor(
    private val spywareCleaner: SpywareCleaner,
    private val settingsRepository: SettingsRepository,
) : ViewModel() {

    private val _liveImplants = MutableStateFlow<List<ImplantFinding>>(emptyList())
    val liveImplants: StateFlow<List<ImplantFinding>> = _liveImplants.asStateFlow()

    private val _isCleaning = MutableStateFlow(false)
    val isCleaning: StateFlow<Boolean> = _isCleaning.asStateFlow()

    private val _lastCleanReport = MutableStateFlow<CleanReport?>(null)
    val lastCleanReport: StateFlow<CleanReport?> = _lastCleanReport.asStateFlow()

    val vpnActive: StateFlow<Boolean> = DnsVpnService.isRunning

    init {
        refreshImplants()
    }

    fun refreshImplants() {
        viewModelScope.launch {
            _liveImplants.value = spywareCleaner.inspectLiveImplants()
        }
    }

    fun cleanThreats(scanPackages: Set<String>) {
        if (_isCleaning.value) return
        viewModelScope.launch {
            _isCleaning.value = true
            try {
                val combined = scanPackages + _liveImplants.value.map { it.packageName }
                val report = spywareCleaner.cleanAndNeutralize(combined)
                _lastCleanReport.value = report
                _liveImplants.value = spywareCleaner.inspectLiveImplants()
            } finally {
                _isCleaning.value = false
            }
        }
    }

    fun armSinkholeSettings() {
        viewModelScope.launch {
            settingsRepository.setBlocklistBlockMode(true)
            settingsRepository.setDomainIocBlockMode(true)
        }
    }

    fun buildUninstallIntent(packageName: String): Intent =
        spywareCleaner.buildUninstallIntent(packageName)

    fun buildAppDetailsIntent(packageName: String): Intent =
        spywareCleaner.buildAppDetailsIntent(packageName)

    fun openHardening(target: SpywareCleaner.HardeningTarget) {
        spywareCleaner.launchHardeningScreen(target)
    }
}
