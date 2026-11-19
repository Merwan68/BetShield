package com.example.service

import java.nio.ByteBuffer

data class DnsQuery(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val ipHeaderLen: Int,
    val dnsTransactionId: Int,
    val domain: String,
    val qType: Int,
    val qClass: Int,
    val dnsPayload: ByteArray,
    val ipVersion: Int = 4,
    val questionEndOffset: Int = dnsPayload.size
)

object DnsPacketHandler {

    /**
     * Parses an IPv4 or IPv6 UDP DNS query packet on port 53. Returns null if not a valid DNS query.
     */
    fun parseQuery(buffer: ByteArray, length: Int): DnsQuery? {
        if (length < 28) return null

        val version = (buffer[0].toInt() and 0xF0) ushr 4
        val ipHeaderLen: Int
        val srcIp: ByteArray
        val dstIp: ByteArray

        when (version) {
            4 -> {
                ipHeaderLen = (buffer[0].toInt() and 0x0F) * 4
                if (ipHeaderLen < 20 || ipHeaderLen + 8 > length) return null
                // Protocol must be UDP (17)
                if ((buffer[9].toInt() and 0xFF) != 17) return null
                srcIp = buffer.copyOfRange(12, 16)
                dstIp = buffer.copyOfRange(16, 20)
            }
            6 -> {
                if (length < 48) return null
                ipHeaderLen = 40
                // Next Header must be UDP (17)
                if ((buffer[6].toInt() and 0xFF) != 17) return null
                srcIp = buffer.copyOfRange(8, 24)
                dstIp = buffer.copyOfRange(24, 40)
            }
            else -> return null
        }

        val udpOffset = ipHeaderLen
        val srcPort = ((buffer[udpOffset].toInt() and 0xFF) shl 8) or (buffer[udpOffset + 1].toInt() and 0xFF)
        val dstPort = ((buffer[udpOffset + 2].toInt() and 0xFF) shl 8) or (buffer[udpOffset + 3].toInt() and 0xFF)

        // Only handle queries sent to port 53
        if (dstPort != 53) return null

        val udpLen = ((buffer[udpOffset + 4].toInt() and 0xFF) shl 8) or (buffer[udpOffset + 5].toInt() and 0xFF)
        if (udpLen < 8 || udpOffset + udpLen > length) return null

        val dnsOffset = udpOffset + 8
        val dnsLen = udpLen - 8
        if (dnsLen < 12) return null

        val dnsPayload = buffer.copyOfRange(dnsOffset, dnsOffset + dnsLen)
        val transactionId = ((dnsPayload[0].toInt() and 0xFF) shl 8) or (dnsPayload[1].toInt() and 0xFF)
        val flags = ((dnsPayload[2].toInt() and 0xFF) shl 8) or (dnsPayload[3].toInt() and 0xFF)

        // QR bit must be 0 (query)
        if ((flags and 0x8000) != 0) return null

        val qdCount = ((dnsPayload[4].toInt() and 0xFF) shl 8) or (dnsPayload[5].toInt() and 0xFF)
        if (qdCount < 1) return null

        // Parse Question domain name
        var pos = 12
        val domainBuilder = StringBuilder()

        while (pos < dnsLen) {
            val labelLen = dnsPayload[pos].toInt() and 0xFF
            if (labelLen == 0) {
                pos++
                break
            }
            // Compression pointer guard
            if ((labelLen and 0xC0) == 0xC0) {
                pos += 2
                break
            }
            pos++
            if (pos + labelLen > dnsLen) return null

            if (domainBuilder.isNotEmpty()) {
                domainBuilder.append(".")
            }
            for (i in 0 until labelLen) {
                domainBuilder.append(dnsPayload[pos + i].toInt().toChar())
            }
            pos += labelLen
        }

        if (pos + 4 > dnsLen) return null
        val qType = ((dnsPayload[pos].toInt() and 0xFF) shl 8) or (dnsPayload[pos + 1].toInt() and 0xFF)
        val qClass = ((dnsPayload[pos + 2].toInt() and 0xFF) shl 8) or (dnsPayload[pos + 3].toInt() and 0xFF)
        val questionEndOffset = pos + 4

        val domain = domainBuilder.toString().trim().trimEnd('.').lowercase()

        return DnsQuery(
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort,
            ipHeaderLen = ipHeaderLen,
            dnsTransactionId = transactionId,
            domain = domain,
            qType = qType,
            qClass = qClass,
            dnsPayload = dnsPayload,
            ipVersion = version,
            questionEndOffset = questionEndOffset
        )
    }

    /**
     * Builds a synthetic DNS response packet resolving blocked domains to 0.0.0.0 (A),
     * :: (AAAA), or NXDOMAIN for other record types (e.g., HTTPS/SVCB).
     */
    fun buildBlockedResponse(query: DnsQuery): ByteArray {
        val safeEnd = query.questionEndOffset.coerceIn(12, query.dnsPayload.size)
        val questionBytes = query.dnsPayload.copyOfRange(12, safeEnd)

        val dnsResponse = ByteBuffer.allocate(512)
        // Transaction ID
        dnsResponse.putShort(query.dnsTransactionId.toShort())

        when (query.qType) {
            1 -> {
                // Type A -> NOERROR, 1 answer (0.0.0.0)
                dnsResponse.putShort(0x8180.toShort())
                dnsResponse.putShort(1) // QDCOUNT
                dnsResponse.putShort(1) // ANCOUNT
                dnsResponse.putShort(0) // NSCOUNT
                dnsResponse.putShort(0) // ARCOUNT
                dnsResponse.put(questionBytes)
                dnsResponse.putShort(0xC00C.toShort())
                dnsResponse.putShort(1) // Type A
                dnsResponse.putShort(1) // Class IN
                dnsResponse.putInt(60) // TTL
                dnsResponse.putShort(4) // RDLENGTH
                dnsResponse.put(byteArrayOf(0, 0, 0, 0))
            }
            28 -> {
                // Type AAAA -> NOERROR, 1 answer (::)
                dnsResponse.putShort(0x8180.toShort())
                dnsResponse.putShort(1) // QDCOUNT
                dnsResponse.putShort(1) // ANCOUNT
                dnsResponse.putShort(0) // NSCOUNT
                dnsResponse.putShort(0) // ARCOUNT
                dnsResponse.put(questionBytes)
                dnsResponse.putShort(0xC00C.toShort())
                dnsResponse.putShort(28) // Type AAAA
                dnsResponse.putShort(1) // Class IN
                dnsResponse.putInt(60) // TTL
                dnsResponse.putShort(16) // RDLENGTH
                dnsResponse.put(ByteArray(16)) // ::
            }
            else -> {
                // HTTPS/SVCB/TXT/etc. -> NXDOMAIN (0x8183)
                dnsResponse.putShort(0x8183.toShort())
                dnsResponse.putShort(1) // QDCOUNT
                dnsResponse.putShort(0) // ANCOUNT
                dnsResponse.putShort(0) // NSCOUNT
                dnsResponse.putShort(0) // ARCOUNT
                dnsResponse.put(questionBytes)
            }
        }

        dnsResponse.flip()
        val dnsBytes = ByteArray(dnsResponse.remaining())
        dnsResponse.get(dnsBytes)

        return wrapInIpUdp(query.ipVersion, query.dstIp, query.srcIp, query.dstPort, query.srcPort, dnsBytes)
    }

    /**
     * Wraps an upstream DNS response payload in IPv4/IPv6 + UDP directed back to the client.
     */
    fun buildForwardResponse(query: DnsQuery, upstreamDnsResponse: ByteArray): ByteArray {
        return wrapInIpUdp(query.ipVersion, query.dstIp, query.srcIp, query.dstPort, query.srcPort, upstreamDnsResponse)
    }

    private fun wrapInIpUdp(
        ipVersion: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        return if (ipVersion == 6 && srcIp.size == 16 && dstIp.size == 16) {
            wrapInIp6Udp(srcIp, dstIp, srcPort, dstPort, payload)
        } else {
            wrapInIp4Udp(srcIp, dstIp, srcPort, dstPort, payload)
        }
    }

    private fun wrapInIp4Udp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalIpLen = 20 + udpLen
        val packet = ByteBuffer.allocate(totalIpLen)

        // --- IPv4 Header (20 bytes) ---
        packet.put(0x45.toByte()) // Version 4, IHL 5
        packet.put(0x00.toByte()) // DSCP / ECN
        packet.putShort(totalIpLen.toShort())
        packet.putShort(0x0000.toShort())
        packet.putShort(0x4000.toShort()) // Don't Fragment
        packet.put(64.toByte()) // TTL
        packet.put(17.toByte()) // Protocol UDP
        packet.putShort(0x0000.toShort()) // Checksum placeholder
        packet.put(srcIp)
        packet.put(dstIp)

        val arr = packet.array()
        val ipChecksum = computeChecksum(arr, 0, 20)
        packet.putShort(10, ipChecksum.toShort())

        // --- UDP Header (8 bytes) ---
        packet.putShort(srcPort.toShort())
        packet.putShort(dstPort.toShort())
        packet.putShort(udpLen.toShort())
        packet.putShort(0x0000.toShort()) // Placeholder

        // --- Payload ---
        packet.put(payload)

        val udpChecksum = computeUdp4Checksum(srcIp, dstIp, arr, 20, udpLen)
        packet.putShort(26, udpChecksum.toShort())

        return arr
    }

    private fun wrapInIp6Udp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 40 + udpLen
        val packet = ByteBuffer.allocate(totalLen)

        // --- IPv6 Header (40 bytes) ---
        packet.put(0x60.toByte()) // Version 6, Traffic Class 0
        packet.put(0x00.toByte())
        packet.put(0x00.toByte())
        packet.put(0x00.toByte())
        packet.putShort(udpLen.toShort()) // Payload Length
        packet.put(17.toByte()) // Next Header: UDP (17)
        packet.put(64.toByte()) // Hop Limit
        packet.put(srcIp)
        packet.put(dstIp)

        // --- UDP Header (8 bytes) ---
        packet.putShort(srcPort.toShort())
        packet.putShort(dstPort.toShort())
        packet.putShort(udpLen.toShort())
        packet.putShort(0x0000.toShort()) // Mandatory checksum placeholder

        // --- Payload ---
        packet.put(payload)

        val arr = packet.array()
        val udpChecksum = computeUdp6Checksum(srcIp, dstIp, arr, 40, udpLen)
        packet.putShort(46, udpChecksum.toShort())

        return arr
    }

    private fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val high = data[i].toInt() and 0xFF
            val low = data[i + 1].toInt() and 0xFF
            sum += (high shl 8) or low
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum ushr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun computeUdp4Checksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        packet: ByteArray,
        udpOffset: Int,
        udpLen: Int
    ): Int {
        var sum = sumBytes(srcIp) + sumBytes(dstIp) + 17 + udpLen + sumBytesRange(packet, udpOffset, udpLen)
        while (sum ushr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val result = sum.inv() and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    private fun computeUdp6Checksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        packet: ByteArray,
        udpOffset: Int,
        udpLen: Int
    ): Int {
        var sum = sumBytes(srcIp) +
            sumBytes(dstIp) +
            (udpLen ushr 16) +
            (udpLen and 0xFFFF) +
            17 +
            sumBytesRange(packet, udpOffset, udpLen)
        while (sum ushr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val result = sum.inv() and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    private fun sumBytes(bytes: ByteArray): Int = sumBytesRange(bytes, 0, bytes.size)

    private fun sumBytesRange(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val high = data[i].toInt() and 0xFF
            val low = data[i + 1].toInt() and 0xFF
            sum += (high shl 8) or low
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        return sum
    }
}
