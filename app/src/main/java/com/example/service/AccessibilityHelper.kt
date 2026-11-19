package com.example.service

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.view.accessibility.AccessibilityManager

object AccessibilityHelper {

    /**
     * Checks if BetShield's AppBlockerAccessibilityService is actively enabled in Android settings.
     */
    fun isAccessibilityServiceEnabled(context: Context): Boolean {
        if (AppBlockerAccessibilityService.isConnected) return true

        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return false
        val enabledServices = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )
        val expectedComponent = ComponentName(context, AppBlockerAccessibilityService::class.java).flattenToString()

        return enabledServices.any { service ->
            service.id.equals(expectedComponent, ignoreCase = true) ||
                    service.resolveInfo?.serviceInfo?.packageName == context.packageName
        }
    }
}
