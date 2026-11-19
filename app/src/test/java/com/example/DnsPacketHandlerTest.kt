package com.example

import com.example.service.DnsPacketHandler
import com.example.service.DnsQuery
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

class DnsPacketHandlerTest {

    private fun buildDnsQuestionPayload(domain: String, qType: Int, txnId: Int, withEdnsOpt: Boolean = false): ByteArray {
        val dnsBuffer = ByteBuffer.allocate(128)
        dnsBuffer.putShort(txnId.toShort())
        dnsBuffer.putShort(0x0100.toShort()) // Standard query
        dnsBuffer.putShort(1) // QDCOUNT
        dnsBuffer.putShort(0)
        dnsBuffer.putShort(0)
        dnsBuffer.putShort(if (withEdnsOpt) 1 else 0) // ARCOUNT

        for (label in domain.split(".")) {
            val bytes = label.toByteArray()
            dnsBuffer.put(bytes.size.toByte())
            dnsBuffer.put(bytes)
        }
        dnsBuffer.put(0.toByte())
        dnsBuffer.putShort(qType.toShort())
        dnsBuffer.putShort(1) // Class IN

        if (withEdnsOpt) {
            // Minimal EDNS0 OPT record (11 bytes)
            dnsBuffer.put(0.toByte())
            dnsBuffer.putShort(41) // OPT
            dnsBuffer.putShort(4096)
            dnsBuffer.putInt(0)
            dnsBuffer.putShort(0)
        }

        dnsBuffer.flip()
        val arr = ByteArray(dnsBuffer.remaining())
        dnsBuffer.get(arr)
        return arr
    }

    private fun buildIp4UdpPacket(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val buf = ByteBuffer.allocate(totalLen)
        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort(0)
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(17.toByte())
        buf.putShort(0)
        buf.put(srcIp)
        buf.put(dstIp)
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0)
        buf.put(payload)
        return buf.array()
    }

    private fun buildIp6UdpPacket(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 40 + udpLen
        val buf = ByteBuffer.allocate(totalLen)
        buf.put(0x60.toByte())
        buf.put(0.toByte())
        buf.put(0.toByte())
        buf.put(0.toByte())
        buf.putShort(udpLen.toShort())
        buf.put(17.toByte())
        buf.put(64.toByte())
        buf.put(srcIp)
        buf.put(dstIp)
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0)
        buf.put(payload)
        return buf.array()
    }

    @Test
    fun testBuildAndParseBlockedResponse() {
        val srcIp = byteArrayOf(10, 1, 10, 2)
        val dstIp = byteArrayOf(10, 1, 10, 1)
        val srcPort = 54321
        val dstPort = 53
        val txnId = 0x1234
        val domain = "bet365.com"

        val dnsPayload = buildDnsQuestionPayload(domain, qType = 1, txnId = txnId, withEdnsOpt = true)
        val rawPacket = buildIp4UdpPacket(srcIp, dstIp, srcPort, dstPort, dnsPayload)

        val parsed = DnsPacketHandler.parseQuery(rawPacket, rawPacket.size)
        assertNotNull(parsed)
        assertEquals(4, parsed!!.ipVersion)
        assertEquals("bet365.com", parsed.domain)

        val blockedPacket = DnsPacketHandler.buildBlockedResponse(parsed)
        assertTrue("Packet should have IP, UDP, and DNS headers", blockedPacket.size > 28)

        // Verify destination port of response is original source port
        val respUdpOffset = 20
        val respDstPort = ((blockedPacket[respUdpOffset + 2].toInt() and 0xFF) shl 8) or
            (blockedPacket[respUdpOffset + 3].toInt() and 0xFF)
        assertEquals(srcPort, respDstPort)

        // Verify transaction ID matches
        val respDnsOffset = respUdpOffset + 8
        val respTxnId = ((blockedPacket[respDnsOffset].toInt() and 0xFF) shl 8) or
            (blockedPacket[respDnsOffset + 1].toInt() and 0xFF)
        assertEquals(txnId, respTxnId)

        // Verify ANCOUNT is 1 (resolved to 0.0.0.0) and ARCOUNT is 0 (EDNS0 OPT cleanly stripped)
        val respAnCount = ((blockedPacket[respDnsOffset + 6].toInt() and 0xFF) shl 8) or
            (blockedPacket[respDnsOffset + 7].toInt() and 0xFF)
        val respArCount = ((blockedPacket[respDnsOffset + 10].toInt() and 0xFF) shl 8) or
            (blockedPacket[respDnsOffset + 11].toInt() and 0xFF)
        assertEquals(1, respAnCount)
        assertEquals(0, respArCount)
    }

    @Test
    fun testIpv6AaaaAndHttpsBlocking() {
        val srcIp6 = ByteArray(16).apply { this[0] = 0xfd.toByte(); this[15] = 2 }
        val dstIp6 = ByteArray(16).apply { this[0] = 0xfd.toByte(); this[15] = 1 }
        val srcPort = 44556

        // Test AAAA (28) over IPv6
        val aaaaPayload = buildDnsQuestionPayload("dash.bet", qType = 28, txnId = 0x5678)
        val rawIp6Aaaa = buildIp6UdpPacket(srcIp6, dstIp6, srcPort, 53, aaaaPayload)
        val parsedAaaa = DnsPacketHandler.parseQuery(rawIp6Aaaa, rawIp6Aaaa.size)
        assertNotNull(parsedAaaa)
        assertEquals(6, parsedAaaa!!.ipVersion)
        assertEquals("dash.bet", parsedAaaa.domain)
        assertEquals(28, parsedAaaa.qType)

        val blockedIp6 = DnsPacketHandler.buildBlockedResponse(parsedAaaa)
        assertEquals(6, (blockedIp6[0].toInt() and 0xF0) ushr 4)
        // IPv6 UDP checksum (offset 46..47) MUST be non-zero
        val udpChecksum = ((blockedIp6[46].toInt() and 0xFF) shl 8) or (blockedIp6[47].toInt() and 0xFF)
        assertTrue("IPv6 UDP checksum must be non-zero", udpChecksum != 0)
        // ANCOUNT = 1 (:: sinkhole)
        val anCount = ((blockedIp6[54].toInt() and 0xFF) shl 8) or (blockedIp6[55].toInt() and 0xFF)
        assertEquals(1, anCount)

        // Test HTTPS record (65) -> NXDOMAIN (0x8183)
        val httpsQuery = DnsQuery(
            srcIp = srcIp6,
            dstIp = dstIp6,
            srcPort = srcPort,
            dstPort = 53,
            ipHeaderLen = 40,
            dnsTransactionId = 0x9999,
            domain = "zplaybet.xyz",
            qType = 65,
            qClass = 1,
            dnsPayload = buildDnsQuestionPayload("zplaybet.xyz", qType = 65, txnId = 0x9999),
            ipVersion = 6
        )
        val blockedHttps = DnsPacketHandler.buildBlockedResponse(httpsQuery)
        val flags = ((blockedHttps[50].toInt() and 0xFF) shl 8) or (blockedHttps[51].toInt() and 0xFF)
        assertEquals(0x8183, flags)
    }
}
