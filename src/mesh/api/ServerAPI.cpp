#include "ServerAPI.h"
#include "Throttle.h"
#ifdef QWICKMESH_TCP_AUTH
#include "HardwareRNG.h"
#endif
#include "configuration.h"
#include <Arduino.h>

static constexpr uint32_t TCP_IDLE_TIMEOUT_MS = 15 * 60 * 1000UL;

template <typename T>
ServerAPI<T>::ServerAPI(T &_client) : StreamAPI(&client), concurrency::OSThread("ServerAPI"), client(_client)
{
#ifdef QWICKMESH_TCP_AUTH
    peerKey = (uint32_t)client.remoteIP();
    secretGen = tcpauth::store().generation();
    LOG_INFO("Incoming API connection, awaiting authentication");
#else
    LOG_INFO("Incoming API connection");
#endif
}

#ifdef QWICKMESH_TCP_AUTH
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
        memset(snonce, 0, sizeof(snonce));
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
#endif

template <typename T> ServerAPI<T>::~ServerAPI()
{
    client.stop();
}

template <typename T> void ServerAPI<T>::close()
{
#ifdef QWICKMESH_TCP_AUTH
    handshake.wipe();
#endif
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
#ifdef QWICKMESH_TCP_AUTH
    if (!isAuthenticated()) {
        if (!client.connected()) {
            close();
            enabled = false;
            return 0;
        }
        runHandshake();
        return 20; // poll the handshake quickly; PhoneAPI is untouched until it passes
    }
    if (!active) {
        // Authenticated, but the port has not yet closed the previous session. Stay off PhoneAPI so sessions never overlap.
        if (!client.connected()) {
            close();
            enabled = false;
            return 0;
        }
        return 20;
    }
#endif
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

#ifdef QWICKMESH_TCP_AUTH
    // Revocation: QMAUTH CLEAR/SET bumps the secret generation. Anything that started under an older generation (an
    // authenticated session or a handshake in flight) is closed immediately, as is everything when no secret is set.
    const bool haveSecret = tcpauth::store().load();
    const auto &secretStore = tcpauth::store();
    if (openAPI && !secretStore.isCurrent(openAPI->generation())) {
        LOG_WARN("TCP API secret changed or cleared, closing authenticated session");
        openAPI.reset();
    }
    if (pendingAPI && !secretStore.isCurrent(pendingAPI->generation())) {
        LOG_WARN("TCP API secret changed or cleared, dropping handshake in flight");
        pendingAPI.reset();
    }

    // Promote or discard the connection that is mid-handshake
    if (pendingAPI) {
        if (pendingAPI->isAuthenticated()) {
            backoff.recordSuccess(pendingAPI->peer());
            if (openAPI) {
                LOG_INFO("Force close previous TCP connection");
                openAPI.reset(); // fully closed before the new session is allowed to run
            }
            pendingAPI->activate();
            openAPI = std::move(pendingAPI);
        } else if (pendingAPI->authFailed()) {
            backoff.recordFailure(pendingAPI->peer(), millis());
            pendingAPI.reset();
        } else if (!pendingAPI->checkIsConnected()) {
            pendingAPI.reset();
        }
    }
#endif

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
#ifdef QWICKMESH_TCP_AUTH
        const uint32_t peerIp = (uint32_t)client.remoteIP();
        if (!haveSecret) {
            // Fail closed: with no secret provisioned the API accepts nothing.
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
#else
        // Close any previous connection (see FIXME in header file)
        if (openAPI) {
#if RAK_4631
            // RAK13800 Ethernet requests periodically take more time
            // This backoff addresses most cases keeping max wait < 1s
            // Reconnections are delayed by full wait time
            if (waitTime < 400) {
                waitTime *= 2;
                LOG_INFO("Previous TCP connection still open, try again in %dms", waitTime);
                return waitTime;
            }
#endif
            LOG_INFO("Force close previous TCP connection");
            openAPI.reset();
        }

        openAPI.reset(new T(client));
#endif
    }

#if RAK_4631
    waitTime = 100;
#endif
    return 100; // only check occasionally for incoming connections
}