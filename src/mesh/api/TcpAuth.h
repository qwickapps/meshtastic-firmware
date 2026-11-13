#pragma once
/**
 * QwickMesh TCP API authentication (protocol "QMA1").
 *
 * Pure logic (no sockets, no Arduino) so it can be unit tested natively and replaced by a TLS-PSK transport later.
 * See DESIGN-wifi-auth.md for the protocol, provisioning flow and threat model.
 *
 *   S -> C : "QMA1" || snonce[16]                                   (20 bytes, sent on accept)
 *   C -> S : cnonce[16] || HMAC-SHA256(K, "QMA1-C" || snonce || cnonce)   (48 bytes)
 *   S -> C : HMAC-SHA256(K, "QMA1-S" || cnonce || snonce)           (32 bytes, only if the client proof verified)
 *
 * After the server proof is written the stream carries the normal 0x94C3 framed ToRadio/FromRadio traffic.
 * Nothing is handed to PhoneAPI before the client proof verifies.
 */

#include <cstddef>
#include <cstdint>

namespace tcpauth
{

constexpr size_t kSecretLen = 32;
constexpr size_t kNonceLen = 16;
constexpr size_t kMacLen = 32;
constexpr size_t kMagicLen = 4;
constexpr size_t kHelloLen = kMagicLen + kNonceLen;      // server -> client
constexpr size_t kResponseLen = kNonceLen + kMacLen;     // client -> server
constexpr uint32_t kHandshakeTimeoutMs = 3000;

/// HMAC-SHA256(key, data...) over up to three segments.
void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen, const uint8_t *c,
                size_t cLen, uint8_t out[kMacLen]);

/// Constant time comparison.
bool constTimeEq(const uint8_t *a, const uint8_t *b, size_t n);

void clientProof(const uint8_t secret[kSecretLen], const uint8_t snonce[kNonceLen], const uint8_t cnonce[kNonceLen],
                 uint8_t out[kMacLen]);
void serverProof(const uint8_t secret[kSecretLen], const uint8_t snonce[kNonceLen], const uint8_t cnonce[kNonceLen],
                 uint8_t out[kMacLen]);

/**
 * Server side handshake state machine. Feed it only the bytes of the client response; it consumes at most kResponseLen bytes
 * and reports how many it still needs so the caller never reads past the handshake into protobuf traffic.
 */
class Handshake
{
  public:
    enum State : uint8_t { AWAIT_RESPONSE, AUTHENTICATED, FAILED };

    /// Starts a handshake. `secret` is copied. `hello` receives kHelloLen bytes to send to the client.
    void begin(const uint8_t secret[kSecretLen], const uint8_t snonce[kNonceLen], uint32_t nowMs, uint8_t hello[kHelloLen]);

    /// Number of response bytes still required (0 once finished).
    size_t needed() const { return state == AWAIT_RESPONSE ? kResponseLen - have : 0; }

    /// Consume response bytes. Returns the new state.
    State feed(const uint8_t *data, size_t len);

    /// Fails the handshake if it has not completed within kHandshakeTimeoutMs.
    State checkTimeout(uint32_t nowMs);

    State getState() const { return state; }

    /// Valid only when AUTHENTICATED: proof the server must send back (mutual authentication).
    const uint8_t *serverProofBytes() const { return proof; }

    /// Wipe secret material.
    void wipe();

  private:
    State state = FAILED;
    uint8_t secret[kSecretLen] = {0};
    uint8_t snonce[kNonceLen] = {0};
    uint8_t resp[kResponseLen] = {0};
    uint8_t proof[kMacLen] = {0};
    size_t have = 0;
    uint32_t startMs = 0;
};

/**
 * Per-peer failure backoff. After kFreeFailures failures the peer is refused for 2^(n-kFreeFailures) seconds, capped.
 * Small fixed table (LRU by last failure); no heap.
 */
class Backoff
{
  public:
    static constexpr size_t kSlots = 8;
    static constexpr uint8_t kFreeFailures = 3;
    static constexpr uint32_t kMaxDelayMs = 5UL * 60UL * 1000UL;

    bool isBlocked(uint32_t peer, uint32_t nowMs) const;
    void recordFailure(uint32_t peer, uint32_t nowMs);
    void recordSuccess(uint32_t peer);
    /// Remaining block in ms (0 if not blocked).
    uint32_t remainingMs(uint32_t peer, uint32_t nowMs) const;

  private:
    struct Slot {
        uint32_t peer = 0;
        uint32_t until = 0;
        uint32_t last = 0;
        uint8_t failures = 0;
        bool used = false;
    };
    Slot slots[kSlots];
};

/**
 * The per-device secret. Stored in its own file (not in the config protobuf) so no config read/backup path can return it.
 * Held in RAM; there is deliberately no accessor that returns it to an API.
 */
class SecretStore
{
  public:
    /// persist=false keeps the secret in RAM only (host tests).
    explicit SecretStore(bool persist = true) : persistToFlash(persist) {}
    /// Load from flash (no-op if already loaded). Returns true if a valid secret is set.
    bool load();
    bool isSet() const { return set; }
    /// Copies the secret for the handshake only.
    bool copyTo(uint8_t out[kSecretLen]) const;
    bool setSecret(const uint8_t s[kSecretLen]); // persists
    void clear();                                 // persists (removes file)
    static constexpr const char *kPath = "/prefs/tcp_auth.key";

  private:
    uint8_t secret[kSecretLen] = {0};
    bool set = false;
    bool loaded = false;
    bool persistToFlash;
};

SecretStore &store();

/// True if `path` (as typed by an API client, e.g. via XModem) refers to the secret file or tries to traverse.
bool isProtectedPath(const char *path);

/// Hex helpers (lowercase/uppercase accepted on decode). decodeHex returns false on bad length/char.
bool decodeHex(const char *hex, size_t hexLen, uint8_t *out, size_t outLen);

/**
 * Serial provisioning line parser. Fed with bytes that are NOT part of a 0x94C3 frame on the USB/UART console:
 *   QMAUTH SET <64 hex>\n   store a new secret
 *   QMAUTH CLEAR\n          remove it (TCP API disabled)
 *   QMAUTH STATUS\n         "set" / "unset" only
 * Only the serial console feeds it; the TCP and BLE paths never do.
 */
class Provisioner
{
  public:
    enum Result : uint8_t { NONE, SET_OK, SET_BAD, CLEARED, STATUS_SET, STATUS_UNSET, IGNORED };
    explicit Provisioner(SecretStore *s = nullptr) : target(s) {}
    /// Returns NONE until a full line has been seen.
    Result feed(uint8_t c);

  private:
    SecretStore *target; // nullptr -> store()
    char line[96];
    size_t n = 0;
    bool overflow = false;
};

} // namespace tcpauth
