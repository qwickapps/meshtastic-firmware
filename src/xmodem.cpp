/**
 * @file xmodem.cpp
 * @brief Implementation of XMODEM protocol for Meshtastic devices.
 *
 * This file contains the implementation of the XMODEM protocol for Meshtastic devices. It is based on the XMODEM implementation
 * by Georges Menie (www.menie.org) and has been adapted for protobuf encapsulation.
 *
 * The XMODEM protocol is used for reliable transmission of binary data over a serial connection. This implementation supports
 * both sending and receiving of data.
 *
 * The XModemAdapter class provides the main functionality for the protocol, including CRC calculation, packet handling, and
 * control signal sending.
 *
 * @copyright Copyright (c) 2001-2019 Georges Menie
 * @author
 * @author
 * @date
 */
/***********************************************************************************************************************
 * based on XMODEM implementation by Georges Menie (www.menie.org)
 ***********************************************************************************************************************
 * Copyright 2001-2019 Georges Menie (www.menie.org)
 * All rights reserved.
 *
 * Adapted for protobuf encapsulation. this is not really Xmodem any more.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **********************************************************************************************************************/

#include "xmodem.h"
#ifdef QWICKMESH_TCP_AUTH
#include "mesh/api/TcpAuth.h"
#endif
#include "SPILock.h"

#ifdef FSCom

XModemAdapter xModem;

XModemAdapter::XModemAdapter() {}

/**
 * Calculates the CRC-16 CCITT checksum of the given buffer.
 *
 * @param buffer The buffer to calculate the checksum for.
 * @param length The length of the buffer.
 * @return The calculated checksum.
 */
unsigned short XModemAdapter::crc16_ccitt(const pb_byte_t *buffer, int length)
{
    unsigned short crc16 = 0;
    while (length != 0) {
        crc16 = (unsigned char)(crc16 >> 8) | (crc16 << 8);
        crc16 ^= *buffer;
        crc16 ^= (unsigned char)(crc16 & 0xff) >> 4;
        crc16 ^= (crc16 << 8) << 4;
        crc16 ^= ((crc16 & 0xff) << 4) << 1;
        buffer++;
        length--;
    }

    return crc16;
}

/**
 * Calculates the checksum of the given buffer and compares it to the given
 * expected checksum. Returns 1 if the checksums match, 0 otherwise.
 *
 * @param buf The buffer to calculate the checksum of.
 * @param sz The size of the buffer.
 * @param tcrc The expected checksum.
 * @return 1 if the checksums match, 0 otherwise.
 */
int XModemAdapter::check(const pb_byte_t *buf, int sz, unsigned short tcrc)
{
    return crc16_ccitt(buf, sz) == tcrc;
}

void XModemAdapter::notifyPacketReady()
{
    storeOwner = requester;
    packetReady.notifyObservers(packetno);
}

void XModemAdapter::sendControl(meshtastic_XModem_Control c)
{
    xmodemStore = meshtastic_XModem_init_zero;
    xmodemStore.control = c;
    LOG_DEBUG("XModem: Notify Send control %d", c);
    notifyPacketReady();
}

meshtastic_XModem XModemAdapter::getForPhone(const PhoneAPI *client)
{
    if (storeOwner && storeOwner != client) {
        meshtastic_XModem none = meshtastic_XModem_init_zero;
        return none;
    }
    return xmodemStore;
}

void XModemAdapter::resetForPhone(const PhoneAPI *client)
{
    if (storeOwner && storeOwner != client)
        return;
    xmodemStore = meshtastic_XModem_init_zero;
    storeOwner = nullptr;
}

void XModemAdapter::abortFor(const PhoneAPI *client)
{
    if (!client)
        return;

    if (storeOwner == client) {
        xmodemStore = meshtastic_XModem_init_zero;
        storeOwner = nullptr;
    }

    if (transferOwner == client) {
        if (isReceiving || isTransmitting) {
            LOG_WARN("XModem: client disconnected during transfer of %s, abort", filename);
            spiLock->lock();
            file.close();
            if (isReceiving)
                FSCom.remove(filename); // incomplete upload, same as CAN
            spiLock->unlock();
        }
        isReceiving = false;
        isTransmitting = false;
        isEOT = false;
        retrans = MAXRETRANS;
        transferOwner = nullptr;
    }
}

bool XModemAdapter::handlePacket(meshtastic_XModem xmodemPacket, const PhoneAPI *client)
{
    if ((isReceiving || isTransmitting) && transferOwner && transferOwner != client) {
        LOG_WARN("XModem: transfer of %s in progress for another client, reject control %d", filename, xmodemPacket.control);
        return false;
    }
    requester = client;

    switch (xmodemPacket.control) {
    case meshtastic_XModem_Control_SOH:
    case meshtastic_XModem_Control_STX:
        if ((xmodemPacket.seq == 0) && !isReceiving && !isTransmitting) {
            // NULL packet has the destination filename
#ifdef QWICKMESH_TCP_AUTH
            // The name must fit with a NUL terminator, otherwise the protected-path scan would read past the buffer
            if (xmodemPacket.buffer.size >= sizeof(filename)) {
                LOG_WARN("XModem: filename too long");
                sendControl(meshtastic_XModem_Control_NAK);
                break;
            }
            memset(filename, 0, sizeof(filename));
            memcpy(filename, &xmodemPacket.buffer.bytes, xmodemPacket.buffer.size);
            // Never let any API client read, overwrite or probe the TCP auth secret file
            if (tcpauth::isProtectedPath(filename)) {
                LOG_WARN("XModem: refusing protected path");
                filename[0] = 0;
                sendControl(meshtastic_XModem_Control_NAK);
                break;
            }
#else
            memcpy(filename, &xmodemPacket.buffer.bytes, xmodemPacket.buffer.size);
#endif

            if (xmodemPacket.control == meshtastic_XModem_Control_SOH) { // Receive this file and put to Flash
                spiLock->lock();
                file = FSCom.open(filename, FILE_O_WRITE);
                spiLock->unlock();
                if (file) {
                    isReceiving = true;
                    transferOwner = client;
                    packetno = 1;
                    sendControl(meshtastic_XModem_Control_ACK);
                    break;
                }
                sendControl(meshtastic_XModem_Control_NAK);
                isReceiving = false;
                break;
            } else { // Transmit this file from Flash
                LOG_INFO("XModem: Transmit file %s", filename);
                spiLock->lock();
                file = FSCom.open(filename, FILE_O_READ);
                spiLock->unlock();
                if (file) {
                    packetno = 1;
                    isTransmitting = true;
                    transferOwner = client;
                    xmodemStore = meshtastic_XModem_init_zero;
                    xmodemStore.control = meshtastic_XModem_Control_SOH;
                    xmodemStore.seq = packetno;
                    spiLock->lock();
                    xmodemStore.buffer.size = file.read(xmodemStore.buffer.bytes, sizeof(meshtastic_XModem_buffer_t::bytes));
                    spiLock->unlock();
                    xmodemStore.crc16 = crc16_ccitt(xmodemStore.buffer.bytes, xmodemStore.buffer.size);
                    LOG_DEBUG("XModem: STX Notify Send packet %d, %d Bytes", packetno, xmodemStore.buffer.size);
                    if (xmodemStore.buffer.size < sizeof(meshtastic_XModem_buffer_t::bytes)) {
                        isEOT = true;
                        // send EOT on next Ack
                    }
                    notifyPacketReady();
                    break;
                }
                sendControl(meshtastic_XModem_Control_NAK);
                isTransmitting = false;
                break;
            }
        } else {
            if (isReceiving) {
                // normal file data packet
                if ((xmodemPacket.seq == packetno) &&
                    check(xmodemPacket.buffer.bytes, xmodemPacket.buffer.size, xmodemPacket.crc16)) {
                    // valid packet
                    spiLock->lock();
                    file.write(xmodemPacket.buffer.bytes, xmodemPacket.buffer.size);
                    spiLock->unlock();
                    sendControl(meshtastic_XModem_Control_ACK);
                    packetno++;
                    break;
                }
                // invalid packet
                sendControl(meshtastic_XModem_Control_NAK);
                break;
            } else if (isTransmitting) {
                // just received something weird.
                sendControl(meshtastic_XModem_Control_CAN);
                isTransmitting = false;
                break;
            }
        }
        break;
    case meshtastic_XModem_Control_EOT:
        // End of transmission
        sendControl(meshtastic_XModem_Control_ACK);
        spiLock->lock();
        file.flush();
        file.close();
        spiLock->unlock();
        isReceiving = false;
        break;
    case meshtastic_XModem_Control_CAN:
        // Cancel transmission and remove file
        sendControl(meshtastic_XModem_Control_ACK);
        spiLock->lock();
        file.flush();
        file.close();

        FSCom.remove(filename);
        spiLock->unlock();
        isReceiving = false;
        break;
    case meshtastic_XModem_Control_ACK:
        // Acknowledge Send the next packet
        if (isTransmitting) {
            if (isEOT) {
                sendControl(meshtastic_XModem_Control_EOT);
                spiLock->lock();
                file.close();
                spiLock->unlock();
                LOG_INFO("XModem: Finished send file %s", filename);
                isTransmitting = false;
                isEOT = false;
                break;
            }
            retrans = MAXRETRANS; // reset retransmit counter
            packetno++;
            xmodemStore = meshtastic_XModem_init_zero;
            xmodemStore.control = meshtastic_XModem_Control_SOH;
            xmodemStore.seq = packetno;
            spiLock->lock();
            xmodemStore.buffer.size = file.read(xmodemStore.buffer.bytes, sizeof(meshtastic_XModem_buffer_t::bytes));
            spiLock->unlock();
            xmodemStore.crc16 = crc16_ccitt(xmodemStore.buffer.bytes, xmodemStore.buffer.size);
            LOG_DEBUG("XModem: ACK Notify Send packet %d, %d Bytes", packetno, xmodemStore.buffer.size);
            if (xmodemStore.buffer.size < sizeof(meshtastic_XModem_buffer_t::bytes)) {
                isEOT = true;
                // send EOT on next Ack
            }
            notifyPacketReady();
        } else {
            // just received something weird.
            sendControl(meshtastic_XModem_Control_CAN);
        }
        break;
    case meshtastic_XModem_Control_NAK:
        // Negative acknowledge. Send the same buffer again
        if (isTransmitting) {
            if (--retrans <= 0) {
                sendControl(meshtastic_XModem_Control_CAN);
                spiLock->lock();
                file.close();
                spiLock->unlock();
                LOG_INFO("XModem: Retransmit timeout, cancel file %s", filename);
                isTransmitting = false;
                break;
            }
            xmodemStore = meshtastic_XModem_init_zero;
            xmodemStore.control = meshtastic_XModem_Control_SOH;
            xmodemStore.seq = packetno;
            spiLock->lock();
            file.seek((packetno - 1) * sizeof(meshtastic_XModem_buffer_t::bytes));

            xmodemStore.buffer.size = file.read(xmodemStore.buffer.bytes, sizeof(meshtastic_XModem_buffer_t::bytes));
            spiLock->unlock();
            xmodemStore.crc16 = crc16_ccitt(xmodemStore.buffer.bytes, xmodemStore.buffer.size);
            LOG_DEBUG("XModem: NAK Notify Send packet %d, %d Bytes", packetno, xmodemStore.buffer.size);
            if (xmodemStore.buffer.size < sizeof(meshtastic_XModem_buffer_t::bytes)) {
                isEOT = true;
                // send EOT on next Ack
            }
            notifyPacketReady();
        } else {
            // just received something weird.
            sendControl(meshtastic_XModem_Control_CAN);
        }
        break;
    default:
        // Unknown control character
        break;
    }

    if (!isReceiving && !isTransmitting)
        transferOwner = nullptr;
    return true;
}
#endif
