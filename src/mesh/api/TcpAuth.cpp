#include "TcpAuth.h"
#ifdef QWICKMESH_TCP_AUTH
#include <Crypto.h>
#include <SHA256.h>
#include <cstring>
#include <strings.h>

#if __has_include("configuration.h")
#include "configuration.h"
#endif
#ifdef FSCom
#include "FSCommon.h"
#include "SPILock.h"
#include "concurrency/LockGuard.h"
#endif

namespace tcpauth
{

void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen, const uint8_t *c,
                size_t cLen, uint8_t out[kMacLen])
{
    SHA256 h;
    h.resetHMAC(key, keyLen);
    if (a && aLen)
        h.update(a, aLen);
    if (b && bLen)
        h.update(b, bLen);
    if (c && cLen)
        h.update(c, cLen);
    h.finalizeHMAC(key, keyLen, out, kMacLen);
}

bool constTimeEq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d == 0;
}

static const uint8_t kLabelC[] = {'Q', 'M', 'A', '1', '-', 'C'};
static const uint8_t kLabelS[] = {'Q', 'M', 'A', '1', '-', 'S'};
static const uint8_t kMagic[kMagicLen] = {'Q', 'M', 'A', '1'};

void clientProof(const uint8_t secret[kSecretLen], const uint8_t snonce[kNonceLen], const uint8_t cnonce[kNonceLen],
                 uint8_t out[kMacLen])
{
    uint8_t msg[sizeof(kLabelC) + 2 * kNonceLen];
    memcpy(msg, kLabelC, sizeof(kLabelC));
    memcpy(msg + sizeof(kLabelC), snonce, kNonceLen);
    memcpy(msg + sizeof(kLabelC) + kNonceLen, cnonce, kNonceLen);
    hmacSha256(secret, kSecretLen, msg, sizeof(msg), nullptr, 0, nullptr, 0, out);
}

void serverProof(const uint8_t secret[kSecretLen], const uint8_t snonce[kNonceLen], const uint8_t cnonce[kNonceLen],
                 uint8_t out[kMacLen])
{
    uint8_t msg[sizeof(kLabelS) + 2 * kNonceLen];
    memcpy(msg, kLabelS, sizeof(kLabelS));
    memcpy(msg + sizeof(kLabelS), cnonce, kNonceLen);
    memcpy(msg + sizeof(kLabelS) + kNonceLen, snonce, kNonceLen);
    hmacSha256(secret, kSecretLen, msg, sizeof(msg), nullptr, 0, nullptr, 0, out);
}

// ---------------------------------------------------------------- Handshake

void Handshake::begin(const uint8_t sec[kSecretLen], const uint8_t sn[kNonceLen], uint32_t nowMs, uint8_t hello[kHelloLen])
{
    memcpy(secret, sec, kSecretLen);
    memcpy(snonce, sn, kNonceLen);
    memset(resp, 0, sizeof(resp));
    memset(proof, 0, sizeof(proof));
    have = 0;
    startMs = nowMs;
    state = AWAIT_RESPONSE;
    memcpy(hello, kMagic, kMagicLen);
    memcpy(hello + kMagicLen, snonce, kNonceLen);
}

Handshake::State Handshake::feed(const uint8_t *data, size_t len)
{
    if (state != AWAIT_RESPONSE)
        return state;
    size_t take = kResponseLen - have;
    if (len < take)
        take = len;
    memcpy(resp + have, data, take);
    have += take;
    if (have < kResponseLen)
        return state;

    uint8_t expect[kMacLen];
    clientProof(secret, snonce, resp, expect); // resp[0..16) is cnonce
    bool ok = constTimeEq(expect, resp + kNonceLen, kMacLen);
    memset(expect, 0, sizeof(expect));
    if (ok) {
        serverProof(secret, snonce, resp, proof);
        state = AUTHENTICATED;
    } else {
        state = FAILED;
    }
    memset(secret, 0, sizeof(secret)); // not needed any more
    if (state == FAILED)
        wipe();
    return state;
}

Handshake::State Handshake::checkTimeout(uint32_t nowMs)
{
    if (state == AWAIT_RESPONSE && (uint32_t)(nowMs - startMs) > kHandshakeTimeoutMs) {
        state = FAILED;
        wipe();
    }
    return state;
}

void Handshake::wipe()
{
    memset(secret, 0, sizeof(secret));
    memset(resp, 0, sizeof(resp));
}

void Handshake::wipeAll()
{
    memset(snonce, 0, sizeof(snonce));
    memset(proof, 0, sizeof(proof));
    have = 0;
    state = FAILED;
}

// ------------------------------------------------------------------ Backoff

static uint32_t delayFor(uint8_t failures)
{
    if (failures < Backoff::kFreeFailures)
        return 0;
    uint32_t shift = failures - Backoff::kFreeFailures;
    if (shift > 10)
        return Backoff::kMaxDelayMs;
    uint32_t ms = 1000UL << shift;
    return ms > Backoff::kMaxDelayMs ? Backoff::kMaxDelayMs : ms;
}

static uint8_t decayed(uint8_t failures, uint32_t lastMs, uint32_t nowMs)
{
    uint32_t periods = (uint32_t)(nowMs - lastMs) / Backoff::kDecayPeriodMs;
    return periods >= failures ? 0 : (uint8_t)(failures - periods);
}

uint8_t Backoff::failuresFor(uint32_t peer, uint32_t nowMs) const
{
    for (const Slot &s : slots)
        if (s.used && s.peer == peer)
            return decayed(s.failures, s.last, nowMs);
    return 0;
}

bool Backoff::isBlocked(uint32_t peer, uint32_t nowMs) const
{
    return remainingMs(peer, nowMs) > 0;
}

uint32_t Backoff::remainingMs(uint32_t peer, uint32_t nowMs) const
{
    for (const Slot &s : slots) {
        if (s.used && s.peer == peer) {
            int32_t left = (int32_t)(s.until - nowMs);
            return left > 0 ? (uint32_t)left : 0;
        }
    }
    return 0;
}

void Backoff::recordFailure(uint32_t peer, uint32_t nowMs)
{
    Slot *victim = &slots[0];
    for (Slot &s : slots) {
        if (s.used && s.peer == peer) {
            victim = &s;
            break;
        }
        if (!s.used) {
            victim = &s;
        } else if (victim->used && (int32_t)(s.last - victim->last) < 0) {
            victim = &s; // least recently failed
        }
    }
    if (!victim->used || victim->peer != peer) {
        *victim = Slot();
        victim->used = true;
        victim->peer = peer;
    }
    victim->failures = decayed(victim->failures, victim->last, nowMs); // forgive failures after quiet time
    if (victim->failures < 255)
        victim->failures++;
    victim->last = nowMs;
    victim->until = nowMs + delayFor(victim->failures);
}

void Backoff::recordSuccess(uint32_t peer)
{
    for (Slot &s : slots)
        if (s.used && s.peer == peer)
            s = Slot();
}

// -------------------------------------------------------------- SecretStore

SecretStore &store()
{
    static SecretStore instance;
    return instance;
}

bool SecretStore::load()
{
    if (loaded)
        return set;
    loaded = true;
#ifdef FSCom
    if (persistToFlash) {
        concurrency::LockGuard g(spiLock);
        auto f = FSCom.open(kPath, FILE_O_READ);
        if (f) {
            uint8_t buf[kSecretLen + 1];
            size_t n = f.read(buf, sizeof(buf));
            f.close();
            if (n == kSecretLen) {
                memcpy(secret, buf, kSecretLen);
                set = true;
            }
            memset(buf, 0, sizeof(buf));
        }
    }
#endif
    return set;
}

bool SecretStore::copyTo(uint8_t out[kSecretLen]) const
{
    if (!set)
        return false;
    memcpy(out, secret, kSecretLen);
    return true;
}

bool SecretStore::setSecret(const uint8_t s[kSecretLen])
{
    if (isWeakSecret(s))
        return false;
#ifdef FSCom
    if (persistToFlash) {
        concurrency::LockGuard g(spiLock);
        FSCom.mkdir("/prefs");
        FSCom.remove(kPath);
        auto f = FSCom.open(kPath, FILE_O_WRITE);
        if (!f)
            return false;
        size_t n = f.write(s, kSecretLen);
        f.flush();
        f.close();
        if (n != kSecretLen) {
            FSCom.remove(kPath);
            return false;
        }
    }
#endif
    memcpy(secret, s, kSecretLen);
    set = true;
    loaded = true;
    gen++;
    return true;
}

void SecretStore::clear()
{
#ifdef FSCom
    if (persistToFlash) {
        concurrency::LockGuard g(spiLock);
        FSCom.remove(kPath);
    }
#endif
    memset(secret, 0, sizeof(secret));
    set = false;
    loaded = true;
    gen++;
}

// ----------------------------------------------------------------- helpers

bool isWeakSecret(const uint8_t s[kSecretLen])
{
    uint8_t diff = 0;
    for (size_t i = 1; i < kSecretLen; i++)
        diff |= s[i] ^ s[0];
    return diff == 0;
}

bool isProtectedPath(const char *path)
{
    if (!path)
        return false;
    // Any traversal, or any mention of the key file name, is refused. Exact-match alone could be bypassed with "//" or "/./".
    if (strstr(path, "..") || strcasestr(path, "tcp_auth"))
        return true;
    return false;
}

static int hexVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool decodeHex(const char *hex, size_t hexLen, uint8_t *out, size_t outLen)
{
    if (hexLen != outLen * 2)
        return false;
    for (size_t i = 0; i < outLen; i++) {
        int hi = hexVal(hex[2 * i]), lo = hexVal(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

Provisioner::Result Provisioner::feed(uint8_t c)
{
    if (c != '\n' && c != '\r') {
        if (n < sizeof(line) - 1)
            line[n++] = (char)c;
        else
            overflow = true;
        return NONE;
    }
    size_t len = n;
    bool ovf = overflow;
    n = 0;
    overflow = false;
    line[len] = 0;
    if (len == 0)
        return NONE;

    Result r = IGNORED;
    SecretStore &st = target ? *target : store();
    if (!ovf && len >= 7 && strncmp(line, "QMAUTH ", 7) == 0) {
        const char *arg = line + 7;
        if (strncmp(arg, "SET ", 4) == 0) {
            uint8_t s[kSecretLen];
            r = (decodeHex(arg + 4, len - 11, s, kSecretLen) && st.setSecret(s)) ? SET_OK : SET_BAD;
            memset(s, 0, sizeof(s));
        } else if (strcmp(arg, "CLEAR") == 0) {
            st.clear();
            r = CLEARED;
        } else if (strcmp(arg, "STATUS") == 0) {
            r = st.isSet() ? STATUS_SET : STATUS_UNSET;
        }
    } else if (ovf && strncmp(line, "QMAUTH ", 7) == 0) {
        r = SET_BAD;
    }
    memset(line, 0, sizeof(line)); // the line may have held the secret
    return r;
}

} // namespace tcpauth

#endif // QWICKMESH_TCP_AUTH
