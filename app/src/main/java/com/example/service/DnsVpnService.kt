package com.example.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.example.MainActivity
import com.example.R
import com.example.data.AppDatabase
import com.example.data.repository.BlockingRepository
import com.example.security.PinManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

class DnsVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetLoopJob: Job? = null
    private lateinit var repository: BlockingRepository
    private lateinit var pinManager: PinManager

    @Volatile
    private var isRunning = false

    @Volatile
    private var cacheInitialized = false
    private val cachedBlockedDomains = ConcurrentHashMap.newKeySet<String>()
    private val recentLoggedDomains = ConcurrentHashMap<String, Long>()

    private val upstreamDnsIps = listOf("1.1.1.1", "8.8.8.8")
    private val localClientIp4 = "10.1.10.2"
    private val localDnsIp4 = "10.1.10.1"
    private val localClientIp6 = "fd00:1:10::2"
    private val localDnsIp6 = "fd00:1:10::1"

    companion object {
        const val ACTION_START = "com.example.service.DnsVpnService.START"
        const val ACTION_STOP = "com.example.service.DnsVpnService.STOP"
        private const val CHANNEL_ID = "betshield_protection_channel"
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            try {
                if (prepare(context) != null) return
                val intent = Intent(context, DnsVpnService::class.java).apply {
                    action = ACTION_START
                }
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        fun stop(context: Context) {
            try {
                val intent = Intent(context, DnsVpnService::class.java).apply {
                    action = ACTION_STOP
                }
                context.startService(intent)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

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
            createNotificationChannel()

            serviceScope.launch {
                repository.activeDomainsFlow.collect { domains ->
                    val activeSet = domains
                        .filter { it.isActive && !it.isDeleted }
                        .map { it.domain.trim().trimEnd('.').lowercase() }
                    cachedBlockedDomains.clear()
                    cachedBlockedDomains.addAll(activeSet)
                    cacheInitialized = true
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                promoteToForeground()
                if (!isRunning) {
                    startVpn()
                }
            }
        }
        return START_STICKY
    }

    private fun promoteToForeground() {
        try {
            val notification = buildNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun startVpn() {
        try {
            if (prepare(this) != null) {
                stopVpn()
                stopSelf()
                return
            }

            val builder = Builder()
                .setSession("BetShield Local DNS Guard")
                .setMtu(1500)
                // Client IP and synthetic DNS server IP MUST differ so packets enter tun0 instead of lo
                .addAddress(localClientIp4, 32)
                .addDnsServer(localDnsIp4)
                .addRoute(localDnsIp4, 32)
                // Intercept queries targeted at popular public IPv4 DNS resolvers
                .addRoute("1.1.1.1", 32)
                .addRoute("1.0.0.1", 32)
                .addRoute("8.8.8.8", 32)
                .addRoute("8.8.4.4", 32)
                .addRoute("9.9.9.9", 32)
                .addRoute("149.112.112.112", 32)
                .addRoute("208.67.222.222", 32)
                .addRoute("208.67.220.220", 32)

            // Configure IPv6 DNS interception so 4G/LTE carrier IPv6 DNS cannot bypass filtering
            try {
                builder
                    .addAddress(localClientIp6, 128)
                    .addDnsServer(localDnsIp6)
                    .addRoute(localDnsIp6, 128)
                    .addRoute("2001:4860:4860::8888", 128)
                    .addRoute("2001:4860:4860::8844", 128)
                    .addRoute("2606:4700:4700::1111", 128)
                    .addRoute("2606:4700:4700::1001", 128)
            } catch (e: Exception) {
                // Continue with IPv4 if kernel/device disables IPv6
                e.printStackTrace()
            }

            // Allow BetShield itself to bypass VPN
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {
            }

            val pfd = builder.establish()
            if (pfd == null) {
                isRunning = false
                stopSelf()
                return
            }

            vpnInterface = pfd
            isRunning = true

            packetLoopJob?.cancel()
            packetLoopJob = serviceScope.launch(Dispatchers.IO) {
                runPacketLoop(pfd)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
            stopSelf()
        }
    }

    private suspend fun isDomainBlockedFast(domain: String): Boolean {
        val cleanHost = domain.trim().trimEnd('.').lowercase().removePrefix("www.")
        if (cleanHost.isBlank() || !cleanHost.contains(".")) return false

        if (cacheInitialized) {
            var current = cleanHost
            while (current.isNotBlank() && current.contains(".")) {
                if (cachedBlockedDomains.contains(current)) return true
                current = current.substringAfter(".", "")
            }
            return false
        }
        return repository.isDomainBlocked(cleanHost)
    }

    private suspend fun runPacketLoop(pfd: ParcelFileDescriptor) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val outputStream = FileOutputStream(pfd.fileDescriptor)
        val buffer = ByteArray(32767)

        val upstreamInetAddresses = upstreamDnsIps.mapNotNull {
            runCatching { InetAddress.getByName(it) }.getOrNull()
        }

        while (serviceScope.isActive && isRunning) {
            try {
                val length = inputStream.read(buffer)
                if (length > 0) {
                    val query = DnsPacketHandler.parseQuery(buffer, length)
                    if (query != null) {
                        val isBlocked = pinManager.isProtectionEnabled && isDomainBlockedFast(query.domain)

                        if (isBlocked) {
                            val responsePacket = DnsPacketHandler.buildBlockedResponse(query)
                            synchronized(outputStream) {
                                outputStream.write(responsePacket)
                                outputStream.flush()
                            }

                            val now = System.currentTimeMillis()
                            val lastLog = recentLoggedDomains[query.domain] ?: 0L
                            if (now - lastLog > 2000L) {
                                recentLoggedDomains[query.domain] = now
                                serviceScope.launch {
                                    try {
                                        val details = repository.getDomainDetails(query.domain)
                                        repository.recordBlockEvent(
                                            target = query.domain,
                                            serviceName = details?.serviceName ?: query.domain,
                                            category = details?.category ?: "Gambling Website",
                                            targetType = "DOMAIN"
                                        )
                                    } catch (e: Exception) {
                                        e.printStackTrace()
                                    }
                                }
                            }
                        } else {
                            serviceScope.launch(Dispatchers.IO) {
                                forwardDnsQuery(query, upstreamInetAddresses, outputStream)
                            }
                        }
                    }
                } else {
                    delay(20)
                }
            } catch (e: Exception) {
                if (!isRunning) break
            }
        }
    }

    private fun forwardDnsQuery(
        query: DnsQuery,
        upstreams: List<InetAddress>,
        outputStream: FileOutputStream
    ) {
        for (upstream in upstreams) {
            try {
                DatagramSocket().use { socket ->
                    if (!protect(socket)) return@use
                    socket.soTimeout = 2500

                    val sendPacket = DatagramPacket(query.dnsPayload, query.dnsPayload.size, upstream, 53)
                    socket.send(sendPacket)

                    val recvBuffer = ByteArray(1500)
                    val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)
                    socket.receive(recvPacket)

                    if (recvPacket.length >= 2) {
                        val responseDnsPayload = recvBuffer.copyOf(recvPacket.length)
                        val ipUdpPacket = DnsPacketHandler.buildForwardResponse(query, responseDnsPayload)
                        synchronized(outputStream) {
                            outputStream.write(ipUdpPacket)
                            outputStream.flush()
                        }
                        return
                    }
                }
            } catch (_: Exception) {
                // Try next upstream
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        packetLoopJob?.cancel()
        packetLoopJob = null
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        vpnInterface = null
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "BetShield Protection Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Notifies when active gambling website & app blocking is operating."
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_notification)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_desc))
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onRevoke() {
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
    }
}
