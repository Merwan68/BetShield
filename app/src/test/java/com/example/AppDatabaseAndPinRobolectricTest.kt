package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.AppDatabase
import com.example.data.InitialGamblingCatalog
import com.example.data.repository.BlockingRepository
import com.example.security.PinManager
import com.example.security.ProtectionLevel
import com.example.service.DnsVpnService
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class AppDatabaseAndPinRobolectricTest {

    private lateinit var context: Context
    private lateinit var db: AppDatabase
    private lateinit var repository: BlockingRepository

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repository = BlockingRepository(
            db.blockedDomainDao(),
            db.blockedAppDao(),
            db.blockEventDao(),
            db.syncMetadataDao()
        )
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun `repository matches subdomains and resolves parent service details`() = runTest {
        db.blockedDomainDao().insertDomainsIfAbsent(InitialGamblingCatalog.defaultDomains)

        assertTrue(repository.isDomainBlocked("dash.bet"))
        assertTrue(repository.isDomainBlocked("www.dash.bet."))
        assertTrue(repository.isDomainBlocked("m.dash.bet"))
        assertTrue(repository.isDomainBlocked("sports.zplaybet.xyz"))
        assertTrue(repository.isDomainBlocked("live.melbet.com"))
        assertFalse(repository.isDomainBlocked("wikipedia.org"))

        val details = repository.getDomainDetails("m.dash.bet")
        assertNotNull(details)
        assertEquals("DashBet", details?.serviceName)
    }

    @Test
    fun `custom domain normalization and toggle preservation work properly`() = runTest {
        db.blockedDomainDao().insertDomainsIfAbsent(InitialGamblingCatalog.defaultDomains)

        // Disable one entry and verify insertDomainsIfAbsent does NOT overwrite user choice
        repository.toggleDomainStatus("bet365.com", false)
        assertFalse(repository.isDomainBlocked("bet365.com"))

        db.blockedDomainDao().insertDomainsIfAbsent(InitialGamblingCatalog.defaultDomains)
        assertFalse(repository.isDomainBlocked("bet365.com"))

        // Add custom URL with scheme/path/port and verify normalization
        val added = repository.addCustomDomain("https://www.customcasino.bet/slots?id=1", "Custom Casino", "Online Casino")
        assertTrue(added)
        assertTrue(repository.isDomainBlocked("play.customcasino.bet"))
    }

    @Test
    fun `pin manager hashes verifies clears and tracks cooldown safely`() {
        val pinManager = PinManager(context)
        pinManager.clearPin()
        assertFalse(pinManager.isPinSet())

        assertFalse(pinManager.setPin("123")) // Too short
        assertTrue(pinManager.setPin("4829"))
        assertTrue(pinManager.isPinSet())
        assertTrue(pinManager.verifyPin("4829"))
        assertFalse(pinManager.verifyPin("0000"))

        pinManager.protectionLevel = ProtectionLevel.STRICT
        assertEquals(ProtectionLevel.STRICT, pinManager.protectionLevel)

        pinManager.startCooldown(15)
        assertTrue(pinManager.isUnderCooldown)
        assertTrue(pinManager.remainingCooldownMinutes in 1..15)

        assertTrue(pinManager.clearPin())
        assertFalse(pinManager.isPinSet())
    }

    @Test
    fun `vpn service start does not throw when vpn permission is not prepared`() {
        DnsVpnService.start(context)
        DnsVpnService.stop(context)
    }
}
