package com.example.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.example.data.AppDatabase
import com.example.data.repository.BlockingRepository
import com.example.security.PinManager
import com.example.security.ProtectionLevel
import com.example.ui.AccessBlockedActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class AppBlockerAccessibilityService : AccessibilityService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var repository: BlockingRepository
    private lateinit var pinManager: PinManager

    // Fast in-memory sets for O(1) instantaneous lookups
    private val cachedBlockedPackages = ConcurrentHashMap.newKeySet<String>()
    private val cachedBlockedDomains = ConcurrentHashMap.newKeySet<String>()

    private var lastBlockedTarget: String? = null
    private var lastBlockedTimestamp: Long = 0

    companion object {
        @Volatile
        var isConnected: Boolean = false
            private set
    }

    private val browserPackages = setOf(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.canary",
        "com.chrome.dev",
        "com.android.browser",
        "com.sec.android.app.sbrowser",
        "com.sec.android.app.sbrowser.beta",
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "org.mozilla.focus",
        "com.brave.browser",
        "com.opera.browser",
        "com.opera.mini.native",
        "com.opera.gx",
        "com.opera.touch",
        "com.microsoft.emmx",
        "com.duckduckgo.mobile.android",
        "com.ecosia.android",
        "com.vivaldi.browser",
        "com.mi.globalbrowser",
        "com.transsion.phoenix",
        "com.UCMobile.intl",
        "com.heytap.browser",
        "com.coloros.browser",
        "com.vivo.browser",
        "com.huawei.browser",
        "com.yandex.browser",
        "com.kiwibrowser.browser"
    )

    override fun onCreate() {
        super.onCreate()
        try {
            val db = AppDatabase.getInstance(this)
            repository = BlockingRepository(
                db.blockedDomainDao(),
                db.blockedAppDao(),
                db.blockEventDao(),
                db.syncMetadataDao()
            )
            pinManager = PinManager(this)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        isConnected = true

        try {
            val info = serviceInfo ?: AccessibilityServiceInfo()
            info.eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
            info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            info.flags = AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            info.notificationTimeout = 50
            serviceInfo = info
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // Synchronize in-memory active package IDs
        serviceScope.launch {
            repository.activeAppsFlow.collect { apps ->
                val newSet = apps.filter { it.isActive && !it.isDeleted }.map { it.packageName }.toSet()
                cachedBlockedPackages.clear()
                cachedBlockedPackages.addAll(newSet)
            }
        }

        // Synchronize in-memory active domain names
        serviceScope.launch {
            repository.activeDomainsFlow.collect { domains ->
                val newSet = domains.filter { it.isActive && !it.isDeleted }
                    .map { it.domain.trim().trimEnd('.').lowercase() }
                    .toSet()
                cachedBlockedDomains.clear()
                cachedBlockedDomains.addAll(newSet)
            }
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || !::pinManager.isInitialized) return
        val eventType = event.eventType
        if (eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
        ) return

        val pkgName = event.packageName?.toString() ?: return
        if (pkgName.isBlank()) return

        // Ignore system and own app packages
        if (pkgName == packageName ||
            pkgName == "com.android.systemui" ||
            pkgName == "com.google.android.apps.nexuslauncher" ||
            pkgName == "com.android.launcher3" ||
            pkgName.startsWith("com.google.android.inputmethod")
        ) {
            return
        }

        if (!pinManager.isProtectionEnabled) return

        val now = System.currentTimeMillis()

        // 1. Check if the foreground app itself is a blocked gambling package
        if (pinManager.protectionLevel != ProtectionLevel.BASIC) {
            val isTargetBlocked = cachedBlockedPackages.contains(pkgName)

            if (isTargetBlocked) {
                if (pkgName == lastBlockedTarget && (now - lastBlockedTimestamp) < 1200) {
                    return
                }
                lastBlockedTarget = pkgName
                lastBlockedTimestamp = now

                // Immediately drop to Home to minimize the gambling app
                performGlobalAction(GLOBAL_ACTION_HOME)

                serviceScope.launch {
                    val appDetails = repository.getAppDetails(pkgName)
                    val serviceName = appDetails?.appName ?: pkgName
                    val category = appDetails?.category ?: "Gambling Application"

                    repository.recordBlockEvent(
                        target = pkgName,
                        serviceName = serviceName,
                        category = category,
                        targetType = "APP"
                    )

                    launchBlockingScreen(pkgName, serviceName, category)
                }
                return
            }
        }

        // 2. Check if user is navigating to a gambling website in a web browser
        if (browserPackages.contains(pkgName)) {
            val rootNode = try { rootInActiveWindow } catch (_: Exception) { null } ?: return
            val detectedDomain = extractDomainFromBrowser(rootNode)
            if (!detectedDomain.isNullOrBlank() && detectedDomain.contains(".")) {
                val isDomainBlocked = cachedBlockedDomains.contains(detectedDomain) ||
                        cachedBlockedDomains.any { detectedDomain.endsWith(".$it") }

                if (isDomainBlocked) {
                    if (detectedDomain == lastBlockedTarget && (now - lastBlockedTimestamp) < 1200) {
                        return
                    }
                    lastBlockedTarget = detectedDomain
                    lastBlockedTimestamp = now

                    // Drop to Home
                    performGlobalAction(GLOBAL_ACTION_HOME)

                    serviceScope.launch {
                        val domainDetails = repository.getDomainDetails(detectedDomain)
                        val serviceName = domainDetails?.serviceName ?: detectedDomain
                        val category = domainDetails?.category ?: "Gambling Website"

                        repository.recordBlockEvent(
                            target = detectedDomain,
                            serviceName = serviceName,
                            category = category,
                            targetType = "DOMAIN"
                        )

                        launchBlockingScreen(detectedDomain, serviceName, category)
                    }
                }
            }
        }
    }

    private fun extractDomainFromBrowser(rootNode: AccessibilityNodeInfo): String? {
        val candidateIds = listOf(
            "com.android.chrome:id/url_bar",
            "com.chrome.beta:id/url_bar",
            "com.sec.android.app.sbrowser:id/location_bar_edit_text",
            "org.mozilla.firefox:id/url_bar_title",
            "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
            "org.mozilla.firefox:id/toolbar",
            "com.brave.browser:id/url_bar",
            "com.opera.browser:id/url_field",
            "com.opera.mini.native:id/url_field",
            "com.microsoft.emmx:id/url_bar",
            "com.duckduckgo.mobile.android:id/omnibarTextInput",
            "com.vivaldi.browser:id/url_bar",
            "com.mi.globalbrowser:id/url",
            "com.transsion.phoenix:id/url"
        )
        for (id in candidateIds) {
            try {
                val nodes = rootNode.findAccessibilityNodeInfosByViewId(id)
                if (!nodes.isNullOrEmpty()) {
                    val text = nodes[0].text?.toString()
                    if (!text.isNullOrBlank()) {
                        val cleaned = cleanDomain(text)
                        if (cleaned.contains(".")) return cleaned
                    }
                }
            } catch (_: Exception) {
            }
        }

        // Fallback: search top-level EditText / URL-bar nodes
        return findDomainInNode(rootNode, 0)
    }

    private fun findDomainInNode(node: AccessibilityNodeInfo, depth: Int): String? {
        if (depth > 5) return null
        try {
            val viewId = node.viewIdResourceName?.lowercase() ?: ""
            val isUrlBarHint = node.className == "android.widget.EditText" ||
                    viewId.contains("url") ||
                    viewId.contains("omnibar") ||
                    viewId.contains("location_bar") ||
                    viewId.contains("address")
            if (isUrlBarHint) {
                val text = node.text?.toString()
                if (!text.isNullOrBlank() && text.contains(".")) {
                    val cleaned = cleanDomain(text)
                    if (cleaned.contains(".")) return cleaned
                }
            }
            val count = node.childCount
            for (i in 0 until count) {
                val child = node.getChild(i)
                if (child != null) {
                    val found = findDomainInNode(child, depth + 1)
                    if (found != null) return found
                }
            }
        } catch (_: Exception) {
        }
        return null
    }

    private fun cleanDomain(rawText: String): String {
        var text = rawText.trim().lowercase()
        if (text.startsWith("https://")) text = text.removePrefix("https://")
        if (text.startsWith("http://")) text = text.removePrefix("http://")
        if (text.startsWith("www.")) text = text.removePrefix("www.")
        text = text.substringBefore("/")
        text = text.substringBefore("?")
        text = text.substringBefore("#")
        text = text.substringBefore(":")
        text = text.trim().trimEnd('.')
        if (text.contains(" ")) return ""
        return text
    }

    private fun launchBlockingScreen(target: String, serviceName: String, category: String) {
        val intent = Intent(this, AccessBlockedActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_NO_ANIMATION
            putExtra("EXTRA_TARGET", target)
            putExtra("EXTRA_SERVICE_NAME", serviceName)
            putExtra("EXTRA_CATEGORY", category)
        }
        startActivity(intent)
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        isConnected = false
        super.onDestroy()
        serviceScope.cancel()
    }
}
