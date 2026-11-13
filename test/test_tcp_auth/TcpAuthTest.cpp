// Native tests for the QMA1 TCP API authentication core (src/mesh/api/TcpAuth.*).
// Known-answer vectors are shared with tools/test_qwickmesh_tcp_auth.py (Python client).
#include "TestUtil.h"
#include "mesh/api/TcpAuth.h"
#include <cstdlib>
#include <cstring>
#include <unity.h>

using namespace tcpauth;

static uint8_t S[32], SN[16], CN[16];

static const char *KAT_CLIENT = "694fbbb86b5aed86ad4bc46cd0cdd13e6209c5d5d8739d7245b0ee62e672bfc6";
static const char *KAT_SERVER = "92605b0a8ba4629d4d0540bdc7a4eada4242d16c1c6d4b6897eabb629d64f53a";

void setUp(void)
{
    for (int i = 0; i < 32; i++)
        S[i] = i;
    for (int i = 0; i < 16; i++) {
        SN[i] = 0x10 + i;
        CN[i] = 0x20 + i;
    }
}
void tearDown(void) {}

static void expectHex(const char *hex, const uint8_t *got, size_t n)
{
    uint8_t want[64];
    TEST_ASSERT_TRUE(decodeHex(hex, n * 2, want, n));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, got, n);
}

static void clientResponse(const uint8_t *secret, const uint8_t *sn, const uint8_t *cn, uint8_t out[kResponseLen])
{
    memcpy(out, cn, kNonceLen);
    clientProof(secret, sn, cn, out + kNonceLen);
}

void test_known_answer_vectors()
{
    uint8_t m[32];
    clientProof(S, SN, CN, m);
    expectHex(KAT_CLIENT, m, 32);
    serverProof(S, SN, CN, m);
    expectHex(KAT_SERVER, m, 32);
}

void test_handshake_success_and_mutual_proof()
{
    Handshake h;
    uint8_t hello[kHelloLen];
    h.begin(S, SN, 1000, hello);
    TEST_ASSERT_EQUAL_MEMORY("QMA1", hello, 4);
    TEST_ASSERT_EQUAL_MEMORY(SN, hello + 4, 16);
    TEST_ASSERT_EQUAL(kResponseLen, h.needed());

    uint8_t r[kResponseLen];
    clientResponse(S, SN, CN, r);
    TEST_ASSERT_EQUAL(Handshake::AUTHENTICATED, h.feed(r, kResponseLen));
    TEST_ASSERT_EQUAL(0, h.needed());
    expectHex(KAT_SERVER, h.serverProofBytes(), 32);
}

void test_handshake_accepts_fragmented_input_and_never_over_consumes()
{
    Handshake h;
    uint8_t hello[kHelloLen];
    h.begin(S, SN, 0, hello);
    uint8_t r[kResponseLen + 8];
    clientResponse(S, SN, CN, r);
    memset(r + kResponseLen, 0x94, 8); // pipelined protobuf frame bytes must be left alone by the caller
    for (size_t i = 0; i < kResponseLen - 1; i++)
        TEST_ASSERT_EQUAL(Handshake::AWAIT_RESPONSE, h.feed(r + i, 1));
    TEST_ASSERT_EQUAL(1, h.needed());
    TEST_ASSERT_EQUAL(Handshake::AUTHENTICATED, h.feed(r + kResponseLen - 1, 1));
}

void test_wrong_secret_fails()
{
    Handshake h;
    uint8_t hello[kHelloLen], r[kResponseLen], bad[32];
    memset(bad, 7, sizeof(bad));
    h.begin(S, SN, 0, hello);
    clientResponse(bad, SN, CN, r);
    TEST_ASSERT_EQUAL(Handshake::FAILED, h.feed(r, kResponseLen));
    TEST_ASSERT_EQUAL(Handshake::FAILED, h.feed(r, kResponseLen)); // stays failed
}

void test_single_bit_flip_in_mac_fails()
{
    for (size_t bit = 0; bit < 8; bit++) {
        Handshake h;
        uint8_t hello[kHelloLen], r[kResponseLen];
        h.begin(S, SN, 0, hello);
        clientResponse(S, SN, CN, r);
        r[kResponseLen - 1] ^= (1u << bit);
        TEST_ASSERT_EQUAL(Handshake::FAILED, h.feed(r, kResponseLen));
    }
}

void test_replay_against_fresh_server_nonce_fails()
{
    uint8_t recorded[kResponseLen], fresh[16], hello[kHelloLen];
    clientResponse(S, SN, CN, recorded);
    for (int i = 0; i < 16; i++)
        fresh[i] = 0x40 + i;
    Handshake h;
    h.begin(S, fresh, 0, hello);
    TEST_ASSERT_EQUAL(Handshake::FAILED, h.feed(recorded, kResponseLen));
}

void test_reflected_server_proof_is_not_a_client_proof()
{
    Handshake h;
    uint8_t hello[kHelloLen], r[kResponseLen];
    h.begin(S, SN, 0, hello);
    memcpy(r, CN, 16);
    serverProof(S, SN, CN, r + 16); // wrong label
    TEST_ASSERT_EQUAL(Handshake::FAILED, h.feed(r, kResponseLen));
}

void test_timeout()
{
    Handshake h;
    uint8_t hello[kHelloLen];
    h.begin(S, SN, 5000, hello);
    TEST_ASSERT_EQUAL(Handshake::AWAIT_RESPONSE, h.checkTimeout(5000 + kHandshakeTimeoutMs));
    TEST_ASSERT_EQUAL(Handshake::FAILED, h.checkTimeout(5000 + kHandshakeTimeoutMs + 1));
    // millis() wrap-around
    h.begin(S, SN, 0xFFFFFF00u, hello);
    TEST_ASSERT_EQUAL(Handshake::AWAIT_RESPONSE, h.checkTimeout(0x100));
    TEST_ASSERT_EQUAL(Handshake::FAILED, h.checkTimeout(0xFFFFFF00u + kHandshakeTimeoutMs + 10));
}

void test_backoff_progression_and_isolation()
{
    Backoff b;
    const uint32_t A = 0x0A000001, B = 0x0A000002;
    uint32_t t = 100000;
    for (int i = 0; i < Backoff::kFreeFailures; i++) {
        TEST_ASSERT_FALSE(b.isBlocked(A, t));
        b.recordFailure(A, t);
    }
    // third failure reaches kFreeFailures -> 1s block
    TEST_ASSERT_TRUE(b.isBlocked(A, t + 500));
    TEST_ASSERT_FALSE(b.isBlocked(A, t + 1001));
    TEST_ASSERT_FALSE(b.isBlocked(B, t)); // other peer unaffected
    b.recordFailure(A, t + 1001);         // 4th -> 2s
    TEST_ASSERT_EQUAL_UINT32(2000, b.remainingMs(A, t + 1001));
    b.recordFailure(A, t + 4000); // 5th -> 4s
    TEST_ASSERT_EQUAL_UINT32(4000, b.remainingMs(A, t + 4000));
    for (int i = 0; i < 40; i++)
        b.recordFailure(A, t + 10000);
    TEST_ASSERT_EQUAL_UINT32(Backoff::kMaxDelayMs, b.remainingMs(A, t + 10000)); // capped
    b.recordSuccess(A);
    TEST_ASSERT_FALSE(b.isBlocked(A, t + 10000));
}

void test_backoff_table_eviction_keeps_working()
{
    Backoff b;
    for (uint32_t i = 0; i < Backoff::kSlots + 4; i++)
        for (int k = 0; k < 4; k++)
            b.recordFailure(0x01000000 + i, 1000 + i);
    TEST_ASSERT_TRUE(b.isBlocked(0x01000000 + Backoff::kSlots + 3, 1000 + Backoff::kSlots + 3 + 1));
}

void test_secret_store_ram_only()
{
    SecretStore st(false);
    TEST_ASSERT_FALSE(st.isSet());
    uint8_t out[32];
    TEST_ASSERT_FALSE(st.copyTo(out));
    TEST_ASSERT_TRUE(st.setSecret(S));
    TEST_ASSERT_TRUE(st.isSet());
    TEST_ASSERT_TRUE(st.copyTo(out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(S, out, 32);
    st.clear();
    TEST_ASSERT_FALSE(st.isSet());
    TEST_ASSERT_FALSE(st.copyTo(out));
}

static Provisioner::Result feedLine(Provisioner &p, const char *line)
{
    Provisioner::Result r = Provisioner::NONE;
    for (const char *c = line; *c; c++)
        r = p.feed((uint8_t)*c);
    TEST_ASSERT_EQUAL(Provisioner::NONE, r); // no result before newline
    return p.feed('\n');
}

void test_provisioner_commands()
{
    SecretStore st(false);
    Provisioner p(&st);
    TEST_ASSERT_EQUAL(Provisioner::STATUS_UNSET, feedLine(p, "QMAUTH STATUS"));
    char cmd[96];
    snprintf(cmd, sizeof(cmd), "QMAUTH SET %s",
             "000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F"); // mixed case ok
    TEST_ASSERT_EQUAL(Provisioner::SET_OK, feedLine(p, cmd));
    uint8_t out[32];
    TEST_ASSERT_TRUE(st.copyTo(out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(S, out, 32);
    TEST_ASSERT_EQUAL(Provisioner::STATUS_SET, feedLine(p, "QMAUTH STATUS"));
    TEST_ASSERT_EQUAL(Provisioner::CLEARED, feedLine(p, "QMAUTH CLEAR"));
    TEST_ASSERT_FALSE(st.isSet());
}

void test_provisioner_rejects_bad_input_and_keeps_old_secret()
{
    SecretStore st(false);
    Provisioner p(&st);
    TEST_ASSERT_TRUE(st.setSecret(S));
    TEST_ASSERT_EQUAL(Provisioner::SET_BAD, feedLine(p, "QMAUTH SET 0011"));
    TEST_ASSERT_EQUAL(Provisioner::SET_BAD,
                      feedLine(p, "QMAUTH SET zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    TEST_ASSERT_EQUAL(Provisioner::SET_BAD, feedLine(p, "QMAUTH SET 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00"));
    TEST_ASSERT_EQUAL(Provisioner::IGNORED, feedLine(p, "hello world"));
    TEST_ASSERT_EQUAL(Provisioner::SET_BAD,
                      feedLine(p, "QMAUTH SET 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                  "0000000000000000000000000000000000000000000000000000")); // overflow
    uint8_t out[32];
    TEST_ASSERT_TRUE(st.copyTo(out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(S, out, 32);
}

void test_protected_paths()
{
    TEST_ASSERT_TRUE(isProtectedPath("/prefs/tcp_auth.key"));
    TEST_ASSERT_TRUE(isProtectedPath("//prefs/./tcp_auth.key"));
    TEST_ASSERT_TRUE(isProtectedPath("/prefs/TCP_AUTH.key"));
    TEST_ASSERT_TRUE(isProtectedPath("/static/../prefs/x"));
    TEST_ASSERT_FALSE(isProtectedPath("/prefs/config.proto"));
    TEST_ASSERT_FALSE(isProtectedPath("/static/rangetest.csv"));
    TEST_ASSERT_FALSE(isProtectedPath(nullptr));
}

void test_const_time_eq()
{
    uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 4}, c[4] = {1, 2, 3, 5};
    TEST_ASSERT_TRUE(constTimeEq(a, b, 4));
    TEST_ASSERT_FALSE(constTimeEq(a, c, 4));
}

void setup()
{
    delay(10);
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_known_answer_vectors);
    RUN_TEST(test_handshake_success_and_mutual_proof);
    RUN_TEST(test_handshake_accepts_fragmented_input_and_never_over_consumes);
    RUN_TEST(test_wrong_secret_fails);
    RUN_TEST(test_single_bit_flip_in_mac_fails);
    RUN_TEST(test_replay_against_fresh_server_nonce_fails);
    RUN_TEST(test_reflected_server_proof_is_not_a_client_proof);
    RUN_TEST(test_timeout);
    RUN_TEST(test_backoff_progression_and_isolation);
    RUN_TEST(test_backoff_table_eviction_keeps_working);
    RUN_TEST(test_secret_store_ram_only);
    RUN_TEST(test_provisioner_commands);
    RUN_TEST(test_provisioner_rejects_bad_input_and_keeps_old_secret);
    RUN_TEST(test_protected_paths);
    RUN_TEST(test_const_time_eq);
    exit(UNITY_END());
}

void loop() {}
