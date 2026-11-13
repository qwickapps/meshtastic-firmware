#pragma once

#include "StreamAPI.h"
#ifdef QWICKMESH_TCP_AUTH
#include "TcpAuth.h"
#endif
#include <memory>

#define SERVER_API_DEFAULT_PORT 4403

/**
 * Provides both debug printing and, if the client starts sending protobufs to us, switches to send/receive protobufs
 * (and starts dropping debug printing - FIXME, eventually those prints should be encapsulated in protobufs).
 */
template <class T> class ServerAPI : public StreamAPI, private concurrency::OSThread
{
  private:
    T client;
#ifdef QWICKMESH_TCP_AUTH
    tcpauth::Handshake handshake;
    bool helloSent = false;
    bool authFailedFlag = false;
    bool active = false; ///< set by APIServerPort once any previous session is closed; PhoneAPI stays idle until then
    uint32_t peerKey = 0;
    uint32_t secretGen = 0; ///< SecretStore generation this connection started under

    /// Drive the challenge-response. No ToRadio/FromRadio byte is touched until this returns true.
    bool runHandshake();
#endif

  public:
    explicit ServerAPI(T &_client);

#ifdef QWICKMESH_TCP_AUTH
    /// True once the client proved knowledge of the device secret.
    bool isAuthenticated() const { return handshake.getState() == tcpauth::Handshake::AUTHENTICATED; }
    /// True if the proof was wrong or the client was too slow (counts towards backoff).
    bool authFailed() const { return authFailedFlag; }
    uint32_t peer() const { return peerKey; }
    uint32_t generation() const { return secretGen; }
    /// Called by the port after the previous session has been closed; only then may this session talk to PhoneAPI.
    void activate()
    {
        active = true;
        lastContactMsec = millis();
    }
#endif

    virtual ~ServerAPI();

    /// override close to also shutdown the TCP link
    virtual void close();

    /// Check the current underlying physical link to see if the client is currently connected
    virtual bool checkIsConnected() override;

  protected:
    /// We override this method to prevent publishing EVENT_SERIAL_CONNECTED/DISCONNECTED for wifi links (we want the board to
    /// stay in the POWERED state to prevent disabling wifi)
    virtual void onConnectionChanged(bool connected) override {}

    virtual int32_t runOnce() override; // Check for dropped client connections
};

/**
 * Listens for incoming connections and does accepts and creates instances of ServerAPI as needed
 */
template <class T, class U> class APIServerPort : public U, private concurrency::OSThread
{
    /** The currently open port
     *
     * FIXME: We currently only allow one open TCP connection at a time, because we depend on the loop() call in this class to
     * delegate to the worker.  Once coroutines are implemented we can relax this restriction.
     */
    std::unique_ptr<T> openAPI;

#ifdef QWICKMESH_TCP_AUTH
    /// A connection that has not yet completed the challenge-response. It never displaces openAPI until it authenticates,
    /// so an unauthenticated LAN client cannot kick the legitimate one.
    std::unique_ptr<T> pendingAPI;
    tcpauth::Backoff backoff;
    bool loggedDisabled = false;
#endif
#if defined(RAK_4631) || defined(RAK11310)
    // Track wait time for RAK13800 Ethernet requests
    int32_t waitTime = 100;
#endif

  public:
    explicit APIServerPort(int port);

    void init();

  protected:
    int32_t runOnce() override;
};
