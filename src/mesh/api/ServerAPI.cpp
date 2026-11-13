#include "ServerAPI.h"
#include "Throttle.h"
#include "HardwareRNG.h"
#include "configuration.h"
#include <Arduino.h>

static constexpr uint32_t TCP_IDLE_TIMEOUT_MS = 15 * 60 * 1000UL;

template <typename T>
ServerAPI<T>::ServerAPI(T &_client) : StreamAPI(&client), concurrency::OSThread("ServerAPI"), client(_client)
{
    peerKey = (uint32_t)client.remoteIP();
    LOG_INFO("Incoming API connection, awaiting authentication");
}

template <typename T> bool ServerAPI<T>::runHandshake()
{
    using tcpauth::Handshake;
    if (isAuthenticated())
        return true;
    if (authFailedFlag)
        return false;

    if (!helloSent) {
        uint8_t secret[tcpauth::kSecretLen];
        uint8_t snonce[tcpauth::kNonceLen];
        uint8_t hello[tcpauth::kHelloLen];
        if (!tcpauth::store().copyTo(secret) || !HardwareRNG::fill(snonce, sizeof(snonce))) {
            memset(secret, 0, sizeof(secret));
            close(); // not the peer's fault (no secret / no entropy): close without counting a failure
            enabled = false;
            return false;
        }
        handshake.begin(secret, snonce, millis(), hello);
        memset(secret, 0, sizeof(secret));
        client.write(hello, sizeof(hello));
        helloSent = true;
        return false;
    }

    // Read only as many bytes as the handshake still needs: anything after them belongs to the framed protobuf stream.
    size_t need = handshake.needed();
    if (need > 0 && client.available() > 0) {
        uint8_t buf[tcpauth::kResponseLen];
        if (need > sizeof(buf))
            need = sizeof(buf);
        int got = client.read(buf, need);
        if (got > 0)
            handshake.feed(buf, (size_t)got);
        memset(buf, 0, sizeof(buf));
    }
    handshake.checkTimeout(millis());

    switch (handshake.getState()) {
    case Handshake::AUTHENTICATED:
        client.write(handshake.serverProofBytes(), tcpauth::kMacLen);
        handshake.wipe();
        lastContactMsec = millis();
        LOG_INFO("API client authenticated");
        return true;
    case Handshake::FAILED:
        LOG_WARN("API client failed authentication, closing");
        authFailedFlag = true;
        close();
        enabled = false;
        return false;
    default:
        return false;
    }
}

template <typename T> ServerAPI<T>::~ServerAPI()
{
    client.stop();
}

template <typename T> void ServerAPI<T>::close()
{
    client.stop(); // drop tcp connection
    StreamAPI::close();
}

/// Check the current underlying physical link to see if the client is currently connected
template <typename T> bool ServerAPI<T>::checkIsConnected()
{
    return client.connected();
}

template <class T> int32_t ServerAPI<T>::runOnce()
{
    if (!isAuthenticated()) {
        if (!client.connected()) {
            close();
            enabled = false;
            return 0;
        }
        runHandshake();
        return 20; // poll the handshake quickly; PhoneAPI is untouched until it passes
    }
    if (client.connected()) {
        if (lastContactMsec > 0 && !Throttle::isWithinTimespanMs(lastContactMsec, TCP_IDLE_TIMEOUT_MS)) {
            LOG_WARN("TCP connection timeout, no data for %lu ms", (unsigned long)(millis() - lastContactMsec));
            close();
            enabled = false;
            return 0;
        }
        return StreamAPI::runOncePart();
    } else {
        LOG_INFO("Client dropped connection, suspend API service");
        close();
        enabled = false; // we no longer need to run
        return 0;
    }
}

template <class T, class U> APIServerPort<T, U>::APIServerPort(int port) : U(port), concurrency::OSThread("ApiServer") {}

template <class T, class U> void APIServerPort<T, U>::init()
{
    U::begin();
}

template <class T, class U> int32_t APIServerPort<T, U>::runOnce()
{
    // Clean up previous connection if its client already disconnected
    if (openAPI && !openAPI->checkIsConnected()) {
        openAPI.reset();
    }

    // Promote or discard the connection that is mid-handshake
    if (pendingAPI) {
        if (pendingAPI->isAuthenticated()) {
            backoff.recordSuccess(pendingAPI->peer());
            if (openAPI) {
                LOG_INFO("Force close previous TCP connection");
                openAPI.reset();
            }
            openAPI = std::move(pendingAPI);
        } else if (pendingAPI->authFailed()) {
            backoff.recordFailure(pendingAPI->peer(), millis());
            pendingAPI.reset();
        } else if (!pendingAPI->checkIsConnected()) {
            pendingAPI.reset();
        }
    }

    // Fail closed: with no secret provisioned the API accepts nothing.
    const bool haveSecret = tcpauth::store().load();

#ifdef ARCH_ESP32
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
    auto client = U::accept();
#else
    auto client = U::available();
#endif
#elif defined(ARCH_RP2040) || defined(ARCH_NRF52)
    auto client = U::accept();
#else
    auto client = U::available();
#endif
    if (client) {
        const uint32_t peerIp = (uint32_t)client.remoteIP();
        if (!haveSecret) {
            if (!loggedDisabled) {
                LOG_WARN("TCP API disabled: no auth secret provisioned (QMAUTH SET over serial)");
                loggedDisabled = true;
            }
            client.stop();
        } else if (backoff.isBlocked(peerIp, millis())) {
            LOG_WARN("TCP API: peer in auth backoff, refusing");
            client.stop();
        } else if (pendingAPI) {
            // One handshake at a time; never displace the established session for an unauthenticated peer.
            client.stop();
        } else {
            loggedDisabled = false;
            pendingAPI.reset(new T(client));
        }
    }

#if RAK_4631
    waitTime = 100;
#endif
    return 100; // only check occasionally for incoming connections
}