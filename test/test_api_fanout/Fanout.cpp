#include "DebugConfiguration.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PhoneAPI.h"
#include "Router.h"
#include "mesh/CryptoEngine.h"
#include "SPILock.h"
#include "TestUtil.h"
#include "mesh-pb-constants.h"
#include "xmodem.h"
#include <cstring>
#include <unity.h>

#if !MESHTASTIC_EXCLUDE_STOREFORWARD
class StoreForwardTestAccess
{
  public:
    static void makeServer(StoreForwardModule &sf, uint32_t records)
    {
        sf.records = records;
        sf.populatePSRAM();
        sf.is_server = true;
    }
    static bool busy(const StoreForwardModule &sf) { return sf.busy; }
    static uint32_t cursor(StoreForwardModule &sf, NodeNum n) { return sf.lastRequest[n]; }
    static int32_t runOnce(StoreForwardModule &sf) { return sf.runOnce(); }
};
#endif

namespace
{

struct DummyClientToken {
    uint8_t value = 0;
};

static PhoneAPI *asClient(DummyClientToken &token)
{
    return reinterpret_cast<PhoneAPI *>(&token);
}

static meshtastic_MeshPacket *allocDecodedPacket(uint32_t id, NodeNum to = 0)
{
    meshtastic_MeshPacket *p = packetPool.allocZeroed();
    TEST_ASSERT_NOT_NULL(p);
    p->id = id;
    p->to = to;
    p->which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p->decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    return p;
}

void test_fanout_packet_delivered_to_all_active_clients_once(void)
{
    MeshService meshService;
    DummyClientToken c1, c2, c3;
    PhoneAPI *client1 = asClient(c1);
    PhoneAPI *client2 = asClient(c2);
    PhoneAPI *client3 = asClient(c3);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client1, MeshService::STATE_SERIAL));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client2, MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client3, MeshService::STATE_WIFI));

    meshService.sendToPhone(allocDecodedPacket(101, 0x1001));

    meshtastic_MeshPacket *p1 = meshService.getForPhone(client1);
    meshtastic_MeshPacket *p2 = meshService.getForPhone(client2);
    meshtastic_MeshPacket *p3 = meshService.getForPhone(client3);

    TEST_ASSERT_NOT_NULL(p1);
    TEST_ASSERT_NOT_NULL(p2);
    TEST_ASSERT_NOT_NULL(p3);
    TEST_ASSERT_EQUAL_UINT32(101, p1->id);
    TEST_ASSERT_EQUAL_UINT32(101, p2->id);
    TEST_ASSERT_EQUAL_UINT32(101, p3->id);

    meshService.releaseToPoolForPhone(client1, p1);
    meshService.releaseToPoolForPhone(client2, p2);
    meshService.releaseToPoolForPhone(client3, p3);

    TEST_ASSERT_NULL(meshService.getForPhone(client1));
    TEST_ASSERT_NULL(meshService.getForPhone(client2));
    TEST_ASSERT_NULL(meshService.getForPhone(client3));
}

void test_slow_client_drop_oldest_fast_client_continuous_delivery(void)
{
    MeshService meshService;
    DummyClientToken fastToken, slowToken;
    PhoneAPI *fastClient = asClient(fastToken);
    PhoneAPI *slowClient = asClient(slowToken);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(fastClient, MeshService::STATE_SERIAL));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(slowClient, MeshService::STATE_WIFI));

    const uint32_t totalPackets = MAX_RX_TOPHONE + 4;
    for (uint32_t i = 1; i <= totalPackets; i++) {
        meshService.sendToPhone(allocDecodedPacket(i, i));

        meshtastic_MeshPacket *fastPacket = meshService.getForPhone(fastClient);
        TEST_ASSERT_NOT_NULL(fastPacket);
        TEST_ASSERT_EQUAL_UINT32(i, fastPacket->id);
        meshService.releaseToPoolForPhone(fastClient, fastPacket);
    }

    const uint32_t firstExpected = totalPackets - MAX_RX_TOPHONE + 1;
    for (uint32_t expectedId = firstExpected; expectedId <= totalPackets; expectedId++) {
        meshtastic_MeshPacket *slowPacket = meshService.getForPhone(slowClient);
        TEST_ASSERT_NOT_NULL(slowPacket);
        TEST_ASSERT_EQUAL_UINT32(expectedId, slowPacket->id);
        meshService.releaseToPoolForPhone(slowClient, slowPacket);
    }

    TEST_ASSERT_NULL(meshService.getForPhone(slowClient));
}

void test_disconnect_cleans_pending_and_inflight_without_breaking_other_clients(void)
{
    MeshService meshService;
    DummyClientToken firstToken, secondToken;
    PhoneAPI *firstClient = asClient(firstToken);
    PhoneAPI *secondClient = asClient(secondToken);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(firstClient, MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(secondClient, MeshService::STATE_WIFI));

    meshService.sendToPhone(allocDecodedPacket(201, 0x2001));
    meshtastic_MeshPacket *firstInflight = meshService.getForPhone(firstClient);
    TEST_ASSERT_NOT_NULL(firstInflight);
    TEST_ASSERT_EQUAL_UINT32(201, firstInflight->id);

    meshService.unregisterPhoneClient(firstClient);

    meshtastic_MeshPacket *secondPacket = meshService.getForPhone(secondClient);
    TEST_ASSERT_NOT_NULL(secondPacket);
    TEST_ASSERT_EQUAL_UINT32(201, secondPacket->id);
    meshService.releaseToPoolForPhone(secondClient, secondPacket);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(firstClient, MeshService::STATE_BLE));
    meshService.sendToPhone(allocDecodedPacket(202, 0x2002));
    meshService.unregisterPhoneClient(firstClient); // pending packet for firstClient is dropped on unregister

    meshtastic_MeshPacket *secondPacket2 = meshService.getForPhone(secondClient);
    TEST_ASSERT_NOT_NULL(secondPacket2);
    TEST_ASSERT_EQUAL_UINT32(202, secondPacket2->id);
    meshService.releaseToPoolForPhone(secondClient, secondPacket2);
}

void test_no_active_clients_replays_packet_to_first_registered_client(void)
{
    MeshService meshService;
    meshService.sendToPhone(allocDecodedPacket(301, 0x3001));

    DummyClientToken token;
    PhoneAPI *client = asClient(token);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client, MeshService::STATE_SERIAL));
    meshtastic_MeshPacket *packet = meshService.getForPhone(client);
    TEST_ASSERT_NOT_NULL(packet);
    TEST_ASSERT_EQUAL_UINT32(301, packet->id);
    meshService.releaseToPoolForPhone(client, packet);
}

void test_api_state_mask_refcount_for_same_state_clients(void)
{
    MeshService meshService;
    DummyClientToken firstToken, secondToken;
    PhoneAPI *firstClient = asClient(firstToken);
    PhoneAPI *secondClient = asClient(secondToken);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(firstClient, MeshService::STATE_SERIAL));
    TEST_ASSERT_TRUE((meshService.api_state_mask & MeshService::apiStateBit(MeshService::STATE_SERIAL)) != 0u);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(secondClient, MeshService::STATE_SERIAL));
    TEST_ASSERT_TRUE((meshService.api_state_mask & MeshService::apiStateBit(MeshService::STATE_SERIAL)) != 0u);

    meshService.unregisterPhoneClient(firstClient);
    TEST_ASSERT_TRUE((meshService.api_state_mask & MeshService::apiStateBit(MeshService::STATE_SERIAL)) != 0u);

    meshService.unregisterPhoneClient(secondClient);
    TEST_ASSERT_EQUAL_UINT32(0u, meshService.api_state_mask);
    TEST_ASSERT_EQUAL(MeshService::STATE_DISCONNECTED, meshService.api_state);
}

void test_fanout_pool_capacity_accounts_for_inflight_all_clients(void)
{
    MeshService meshService;
    DummyClientToken tokens[MAX_PHONE_API_CLIENTS];
    PhoneAPI *clients[MAX_PHONE_API_CLIENTS] = {};
    meshtastic_MeshPacket *heldInflight[MAX_PHONE_API_CLIENTS] = {};

    for (int i = 0; i < MAX_PHONE_API_CLIENTS; i++) {
        clients[i] = asClient(tokens[i]);
        TEST_ASSERT_TRUE(meshService.registerPhoneClient(clients[i], MeshService::STATE_SERIAL));
    }

    for (uint32_t i = 1; i <= MAX_RX_TOPHONE; i++) {
        meshService.sendToPhone(allocDecodedPacket(4000 + i, 0x4000 + i));
    }

    for (int i = 0; i < MAX_PHONE_API_CLIENTS; i++) {
        heldInflight[i] = meshService.getForPhone(clients[i]);
        TEST_ASSERT_NOT_NULL(heldInflight[i]);
    }

    const uint32_t extraPacketId = 4999;
    meshService.sendToPhone(allocDecodedPacket(extraPacketId, 0x4999));

    for (int i = 0; i < MAX_PHONE_API_CLIENTS; i++) {
        meshService.releaseToPoolForPhone(clients[i], heldInflight[i]);
        heldInflight[i] = nullptr;

        bool sawExtraPacket = false;
        for (int q = 0; q < MAX_RX_TOPHONE; q++) {
            meshtastic_MeshPacket *p = meshService.getForPhone(clients[i]);
            TEST_ASSERT_NOT_NULL(p);
            if (p->id == extraPacketId) {
                sawExtraPacket = true;
            }
            meshService.releaseToPoolForPhone(clients[i], p);
            if (sawExtraPacket)
                break;
        }
        TEST_ASSERT_TRUE(sawExtraPacket);
    }
}

void test_register_overflow_does_not_change_state_mask_or_existing_delivery(void)
{
    MeshService meshService;
    DummyClientToken tokens[MAX_PHONE_API_CLIENTS];
    PhoneAPI *clients[MAX_PHONE_API_CLIENTS] = {};

    for (int i = 0; i < MAX_PHONE_API_CLIENTS; i++) {
        clients[i] = asClient(tokens[i]);
        MeshService::APIState state = (i % 2 == 0) ? MeshService::STATE_SERIAL : MeshService::STATE_WIFI;
        TEST_ASSERT_TRUE(meshService.registerPhoneClient(clients[i], state));
    }

    uint32_t expectedMask = MeshService::apiStateBit(MeshService::STATE_SERIAL) | MeshService::apiStateBit(MeshService::STATE_WIFI);
    TEST_ASSERT_EQUAL_UINT32(expectedMask, meshService.api_state_mask);

    DummyClientToken overflowToken;
    PhoneAPI *overflowClient = asClient(overflowToken);
    TEST_ASSERT_FALSE(meshService.registerPhoneClient(overflowClient, MeshService::STATE_BLE));
    TEST_ASSERT_EQUAL_UINT32(expectedMask, meshService.api_state_mask);

    meshService.sendToPhone(allocDecodedPacket(5001, 0x5001));

    for (int i = 0; i < MAX_PHONE_API_CLIENTS; i++) {
        meshtastic_MeshPacket *p = meshService.getForPhone(clients[i]);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_UINT32(5001, p->id);
        meshService.releaseToPoolForPhone(clients[i], p);
    }

    TEST_ASSERT_NULL(meshService.getForPhone(overflowClient));
}

// 1b: BLE onDisconnect used to call PhoneAPI::close() on the NimBLE task while the main task held packetForPhone. The
// close now runs on the main task, but MeshService must still tolerate the order "slot torn down, then the client's
// late release of the packet it was holding" without freeing the payload twice, and a reconnect of the same PhoneAPI
// must start clean.
void test_close_from_other_context_then_late_release_is_safe(void)
{
    MeshService meshService;
    DummyClientToken bleToken, uiToken;
    PhoneAPI *bleClient = asClient(bleToken);
    PhoneAPI *uiClient = asClient(uiToken);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(bleClient, MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(uiClient, MeshService::STATE_PACKET));

    meshService.sendToPhone(allocDecodedPacket(601, 0x6001));
    meshtastic_MeshPacket *held = meshService.getForPhone(bleClient); // "main task" is inside getFromRadio
    TEST_ASSERT_NOT_NULL(held);

    meshService.unregisterPhoneClient(bleClient);         // disconnect tears the slot down first
    meshService.releaseToPoolForPhone(bleClient, held);  // late release: must be a no-op, not a double free
    meshService.unregisterPhoneClient(bleClient);         // a second close is harmless too

    // The other client still owns its reference to the shared payload.
    meshtastic_MeshPacket *uiPacket = meshService.getForPhone(uiClient);
    TEST_ASSERT_NOT_NULL(uiPacket);
    TEST_ASSERT_EQUAL_UINT32(601, uiPacket->id);
    meshService.releaseToPoolForPhone(uiClient, uiPacket);

    // Reconnect of the same BLE PhoneAPI: no stale state, receives new traffic.
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(bleClient, MeshService::STATE_BLE));
    TEST_ASSERT_NULL(meshService.getForPhone(bleClient));
    meshService.sendToPhone(allocDecodedPacket(602, 0x6002));
    meshtastic_MeshPacket *fresh = meshService.getForPhone(bleClient);
    TEST_ASSERT_NOT_NULL(fresh);
    TEST_ASSERT_EQUAL_UINT32(602, fresh->id);
    meshService.releaseToPoolForPhone(bleClient, fresh);
    meshtastic_MeshPacket *uiPacket2 = meshService.getForPhone(uiClient);
    TEST_ASSERT_NOT_NULL(uiPacket2);
    meshService.releaseToPoolForPhone(uiClient, uiPacket2);
}

// 2: a packet replayed from the store-and-forward history reaches every registered client, not just the first poller.
void test_store_forward_packet_fanned_out_to_every_client(void)
{
    MeshService meshService;
    DummyClientToken t1, t2, t3;
    PhoneAPI *clients[] = {asClient(t1), asClient(t2), asClient(t3)};
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(clients[0], MeshService::STATE_PACKET));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(clients[1], MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(clients[2], MeshService::STATE_SERIAL));

    TEST_ASSERT_TRUE(meshService.canAcceptStoreForwardPacket());
    meshService.sendStoreForwardToPhone(allocDecodedPacket(701, NODENUM_BROADCAST));

    for (auto *client : clients) {
        meshtastic_MeshPacket *p = meshService.getForPhone(client);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_UINT32(701, p->id);
        meshService.releaseToPoolForPhone(client, p);
        TEST_ASSERT_NULL(meshService.getForPhone(client));
    }
}

// 2: the S&F history is only drained while it can reach a client without displacing anything.
void test_store_forward_gated_on_live_client_with_room(void)
{
    MeshService meshService;
    TEST_ASSERT_FALSE(meshService.canAcceptStoreForwardPacket()); // nobody to deliver to: keep it in the history

    DummyClientToken fastToken, fullToken;
    PhoneAPI *fast = asClient(fastToken);
    PhoneAPI *full = asClient(fullToken);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(fast, MeshService::STATE_PACKET));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(full, MeshService::STATE_BLE));

    for (uint32_t i = 0; i < MAX_RX_TOPHONE; i++) {
        TEST_ASSERT_TRUE(meshService.canAcceptStoreForwardPacket());
        meshService.sendStoreForwardToPhone(allocDecodedPacket(800 + i, NODENUM_BROADCAST));
        meshtastic_MeshPacket *p = meshService.getForPhone(fast);
        TEST_ASSERT_NOT_NULL(p);
        meshService.releaseToPoolForPhone(fast, p);
    }
    // `full` has not drained anything but is not stale yet: no more history may be pulled.
    TEST_ASSERT_FALSE(meshService.canAcceptStoreForwardPacket());

    meshtastic_MeshPacket *p = meshService.getForPhone(full);
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_UINT32(800, p->id);
    meshService.releaseToPoolForPhone(full, p);
    TEST_ASSERT_TRUE(meshService.canAcceptStoreForwardPacket());

    meshService.unregisterPhoneClient(full);
    meshService.unregisterPhoneClient(fast);
    TEST_ASSERT_FALSE(meshService.canAcceptStoreForwardPacket());
}

#if !MESHTASTIC_EXCLUDE_STOREFORWARD
class FanoutTestRouter : public Router
{
  public:
    ~FanoutTestRouter()
    {
        delete cryptLock; // created by the Router constructor
        cryptLock = NULL;
    }
};

// 1: the local S&F drain (MeshService::loop) can stop part way, e.g. when a client queue is full. That must leave no
// state behind that makes runOnce() send the rest of the local history to ourselves as STORE_FORWARD_APP.
void test_store_forward_interrupted_local_drain_keeps_local_cursor(void)
{
    Router *previousRouter = router;
    NodeDB *previousNodeDB = nodeDB;
    const meshtastic_ModuleConfig_StoreForwardConfig previousSF = moduleConfig.store_forward;
    FanoutTestRouter testRouter;
    router = &testRouter;
    if (!nodeDB)
        nodeDB = new NodeDB();
    moduleConfig.store_forward.enabled = true;
    moduleConfig.store_forward.is_server = false;

    {
        StoreForwardModule sf;
        StoreForwardTestAccess::makeServer(sf, 8);
        const NodeNum local = nodeDB->getNodeNum();
        const NodeNum remote = local ^ 0x5a5a;

        for (uint32_t i = 0; i < 3; i++) {
            meshtastic_MeshPacket mp = meshtastic_MeshPacket_init_zero;
            mp.from = remote;
            mp.to = NODENUM_BROADCAST;
            mp.id = 900 + i;
            mp.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
            mp.decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
            mp.decoded.payload.size = 1;
            mp.decoded.payload.bytes[0] = 'a' + i;
            sf.historyAdd(mp);
        }

        meshtastic_MeshPacket *first = sf.getForPhone(); // drain pulls one, then stops (client queue full)
        TEST_ASSERT_NOT_NULL(first);
        TEST_ASSERT_EQUAL_UINT32(900, first->id);
        TEST_ASSERT_EQUAL(meshtastic_PortNum_TEXT_MESSAGE_APP, first->decoded.portnum);
        packetPool.release(first);
        TEST_ASSERT_FALSE(StoreForwardTestAccess::busy(sf));
        TEST_ASSERT_EQUAL_UINT32(1, StoreForwardTestAccess::cursor(sf, local));

        StoreForwardTestAccess::runOnce(sf);
        TEST_ASSERT_EQUAL_UINT32(1, StoreForwardTestAccess::cursor(sf, local));

        // The drain picks up where it stopped, as text.
        for (uint32_t i = 1; i < 3; i++) {
            meshtastic_MeshPacket *p = sf.getForPhone();
            TEST_ASSERT_NOT_NULL(p);
            TEST_ASSERT_EQUAL_UINT32(900 + i, p->id);
            TEST_ASSERT_EQUAL(meshtastic_PortNum_TEXT_MESSAGE_APP, p->decoded.portnum);
            packetPool.release(p);
        }
        TEST_ASSERT_NULL(sf.getForPhone());
    }

    moduleConfig.store_forward = previousSF;
    if (nodeDB != previousNodeDB) {
        delete nodeDB;
        nodeDB = previousNodeDB;
    }
    router = previousRouter;
}
#endif

#ifdef FSCom
static meshtastic_XModem xmodemControl(meshtastic_XModem_Control control, uint16_t seq = 0, const char *name = nullptr)
{
    meshtastic_XModem pkt = meshtastic_XModem_init_zero;
    pkt.control = control;
    pkt.seq = seq;
    if (name) {
        pkt.buffer.size = strlen(name) + 1;
        memcpy(pkt.buffer.bytes, name, pkt.buffer.size);
    }
    return pkt;
}

// 3: responses are addressed to the client whose packet produced them.
void test_xmodem_response_only_visible_to_requesting_client(void)
{
    XModemAdapter adapter;
    DummyClientToken aToken, bToken;
    PhoneAPI *a = asClient(aToken);
    PhoneAPI *b = asClient(bToken);

    // Download of a file that does not exist: immediate NAK for A, no transfer started.
    TEST_ASSERT_TRUE(adapter.handlePacket(xmodemControl(meshtastic_XModem_Control_STX, 0, "/no/such/xmodem/file"), a));
    TEST_ASSERT_FALSE(adapter.isBusy());

    TEST_ASSERT_EQUAL(meshtastic_XModem_Control_NUL, adapter.getForPhone(b).control);
    adapter.resetForPhone(b); // must not clear A's response
    TEST_ASSERT_EQUAL(meshtastic_XModem_Control_NAK, adapter.getForPhone(a).control);
    adapter.resetForPhone(a);
    TEST_ASSERT_EQUAL(meshtastic_XModem_Control_NUL, adapter.getForPhone(a).control);
}

// 3: a running transfer belongs to the client that started it; disconnecting that client aborts it.
void test_xmodem_transfer_bound_to_owner_and_aborted_on_close(void)
{
    XModemAdapter adapter;
    DummyClientToken aToken, bToken;
    PhoneAPI *a = asClient(aToken);
    PhoneAPI *b = asClient(bToken);

    TEST_ASSERT_TRUE(adapter.handlePacket(xmodemControl(meshtastic_XModem_Control_SOH, 0, "/xmodem_fanout_test.bin"), a));
    if (!adapter.isBusy())
        TEST_IGNORE_MESSAGE("filesystem not writable in this environment");
    TEST_ASSERT_EQUAL_PTR(a, adapter.getTransferOwner());
    TEST_ASSERT_EQUAL(meshtastic_XModem_Control_ACK, adapter.getForPhone(a).control);
    adapter.resetForPhone(a);

    // B cannot start, cancel or feed A's transfer.
    TEST_ASSERT_FALSE(adapter.handlePacket(xmodemControl(meshtastic_XModem_Control_SOH, 0, "/other.bin"), b));
    TEST_ASSERT_FALSE(adapter.handlePacket(xmodemControl(meshtastic_XModem_Control_CAN), b));
    TEST_ASSERT_TRUE(adapter.isBusy());
    TEST_ASSERT_EQUAL(meshtastic_XModem_Control_NUL, adapter.getForPhone(b).control);

    adapter.abortFor(b); // not the owner: no effect
    TEST_ASSERT_TRUE(adapter.isBusy());
    adapter.abortFor(a); // owner disconnected
    TEST_ASSERT_FALSE(adapter.isBusy());
    TEST_ASSERT_NULL(adapter.getTransferOwner());

    // Now B may start a transfer.
    TEST_ASSERT_TRUE(adapter.handlePacket(xmodemControl(meshtastic_XModem_Control_STX, 0, "/no/such/xmodem/file"), b));
    TEST_ASSERT_EQUAL(meshtastic_XModem_Control_NAK, adapter.getForPhone(b).control);
}

class XModemTestPhoneAPI : public PhoneAPI
{
  public:
    XModemTestPhoneAPI() { api_type = TYPE_SERIAL; }
    void startConfig() { handleStartConfig(); }
    void sendXModem(const meshtastic_XModem &x)
    {
        meshtastic_ToRadio tr = meshtastic_ToRadio_init_zero;
        tr.which_payload_variant = meshtastic_ToRadio_xmodemPacket_tag;
        tr.xmodemPacket = x;
        uint8_t buf[meshtastic_ToRadio_size];
        size_t len = pb_encode_to_bytes(buf, sizeof(buf), &meshtastic_ToRadio_msg, &tr);
        handleToRadio(buf, len);
    }

  protected:
    bool checkIsConnected() override { return true; }
};

// 4: a client without a config session cannot own a transfer, and closing a client always releases its transfer, so a
// deleted PhoneAPI is never left as owner.
void test_xmodem_owner_released_on_every_close(void)
{
    MeshService meshService;
    MeshService *previousService = service;
    service = &meshService;

    {
        XModemTestPhoneAPI unconfigured;
        unconfigured.sendXModem(xmodemControl(meshtastic_XModem_Control_SOH, 0, "/xmodem_unconfigured.bin"));
        TEST_ASSERT_FALSE(xModem.isBusy());
        TEST_ASSERT_NULL(xModem.getTransferOwner());
    }

    {
        XModemTestPhoneAPI client;
        client.startConfig();
        TEST_ASSERT_TRUE(client.isConnected());
        client.sendXModem(xmodemControl(meshtastic_XModem_Control_SOH, 0, "/xmodem_close_test.bin"));
        if (xModem.isBusy())
            TEST_ASSERT_EQUAL_PTR(&client, xModem.getTransferOwner());
    } // ~PhoneAPI -> close()

    TEST_ASSERT_FALSE(xModem.isBusy());
    TEST_ASSERT_NULL(xModem.getTransferOwner());
    service = previousService;
}
#endif

class RejectedTestPhoneAPI : public PhoneAPI
{
  public:
    RejectedTestPhoneAPI() { api_type = TYPE_SERIAL; }
    void startConfig() { handleStartConfig(); }

  protected:
    bool checkIsConnected() override { return true; }
};

// 9: a client that cannot get a fanout slot is told so instead of hanging silently.
void test_rejected_client_receives_error_notification(void)
{
    MeshService meshService;
    MeshService *previousService = service;
    service = &meshService;

    DummyClientToken tokens[MAX_PHONE_API_CLIENTS];
    for (int i = 0; i < MAX_PHONE_API_CLIENTS; i++)
        TEST_ASSERT_TRUE(meshService.registerPhoneClient(asClient(tokens[i]), MeshService::STATE_PACKET));
    const uint32_t maskBefore = meshService.api_state_mask;

    {
        RejectedTestPhoneAPI rejected;
        rejected.startConfig();
        TEST_ASSERT_FALSE(rejected.isConnected());
        TEST_ASSERT_EQUAL_UINT32(maskBefore, meshService.api_state_mask);

        TEST_ASSERT_TRUE(rejected.available());
        uint8_t buf[meshtastic_FromRadio_size];
        size_t len = rejected.getFromRadio(buf);
        TEST_ASSERT_TRUE(len > 0u);

        meshtastic_FromRadio fr = meshtastic_FromRadio_init_zero;
        TEST_ASSERT_TRUE(pb_decode_from_bytes(buf, len, &meshtastic_FromRadio_msg, &fr));
        TEST_ASSERT_EQUAL(meshtastic_FromRadio_clientNotification_tag, fr.which_payload_variant);
        TEST_ASSERT_EQUAL(meshtastic_LogRecord_Level_ERROR, fr.clientNotification.level);
        TEST_ASSERT_NOT_NULL(strstr(fr.clientNotification.message, "Too many clients"));

        // Sent once; afterwards the client is simply not served until a slot frees up.
        TEST_ASSERT_FALSE(rejected.available());
        TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)rejected.getFromRadio(buf));
    } // ~PhoneAPI -> close() must be safe for a never-registered client

    TEST_ASSERT_EQUAL_UINT32(maskBefore, meshService.api_state_mask);
    service = previousService;
}

} // namespace

void setUp(void) {}
void tearDown(void) {}

void setup()
{
    initializeTestEnvironment();
    if (!spiLock)
        initSPI(); // xmodem file access takes the SPI lock

    UNITY_BEGIN();
    RUN_TEST(test_fanout_packet_delivered_to_all_active_clients_once);
    RUN_TEST(test_slow_client_drop_oldest_fast_client_continuous_delivery);
    RUN_TEST(test_disconnect_cleans_pending_and_inflight_without_breaking_other_clients);
    RUN_TEST(test_no_active_clients_replays_packet_to_first_registered_client);
    RUN_TEST(test_api_state_mask_refcount_for_same_state_clients);
    RUN_TEST(test_fanout_pool_capacity_accounts_for_inflight_all_clients);
    RUN_TEST(test_register_overflow_does_not_change_state_mask_or_existing_delivery);
    RUN_TEST(test_close_from_other_context_then_late_release_is_safe);
    RUN_TEST(test_store_forward_packet_fanned_out_to_every_client);
    RUN_TEST(test_store_forward_gated_on_live_client_with_room);
#if !MESHTASTIC_EXCLUDE_STOREFORWARD
    RUN_TEST(test_store_forward_interrupted_local_drain_keeps_local_cursor);
#endif
#ifdef FSCom
    RUN_TEST(test_xmodem_response_only_visible_to_requesting_client);
    RUN_TEST(test_xmodem_transfer_bound_to_owner_and_aborted_on_close);
    RUN_TEST(test_xmodem_owner_released_on_every_close);
#endif
    RUN_TEST(test_rejected_client_receives_error_notification);
    exit(UNITY_END());
}

void loop() {}
