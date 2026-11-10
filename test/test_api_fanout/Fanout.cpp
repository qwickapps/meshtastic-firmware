#include "DebugConfiguration.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PhoneAPI.h"
#include "Router.h"
#include "SPILock.h"
#include "BleSlotTable.h"
#include "SessionHandoffQueue.h"
#include "TestUtil.h"
#include "concurrency/LockGuard.h"
#include "mesh-pb-constants.h"
#include "mesh/CryptoEngine.h"
#include "xmodem.h"
#include <cstring>
#include <unity.h>
#include <vector>

class MeshServiceTestAccess
{
  public:
    /// Pretend the client last drained a packet `ms` ago.
    static void ageClient(MeshService &service, PhoneAPI *client, uint32_t ms)
    {
        concurrency::LockGuard guard(&service.phoneClientsLock);
        int i = service.findClientSlotByPtrLocked(client);
        TEST_ASSERT_TRUE(i >= 0);
        service.phoneClients[i].lastDrainMsec = millis() - ms;
    }
    static bool isSuspended(MeshService &service, PhoneAPI *client)
    {
        concurrency::LockGuard guard(&service.phoneClientsLock);
        int i = service.findClientSlotByPtrLocked(client);
        return i >= 0 && service.phoneClients[i].suspended;
    }
    static constexpr uint32_t kStaleMs = MeshService::kStaleClientDrainMs;
};

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

static meshtastic_MeshPacket *allocDecodedPacket(uint32_t id, NodeNum to = 0,
                                                 meshtastic_PortNum portnum = meshtastic_PortNum_TEXT_MESSAGE_APP)
{
    meshtastic_MeshPacket *p = packetPool.allocZeroed();
    TEST_ASSERT_NOT_NULL(p);
    p->id = id;
    p->to = to;
    p->which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p->decoded.portnum = portnum;
    return p;
}

static meshtastic_MeshPacket *allocTelemetryPacket(uint32_t id)
{
    return allocDecodedPacket(id, NODENUM_BROADCAST, meshtastic_PortNum_TELEMETRY_APP);
}

static void expectDrainOrder(MeshService &meshService, PhoneAPI *client, const uint32_t *ids, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        meshtastic_MeshPacket *p = meshService.getForPhone(client);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_UINT32(ids[i], p->id);
        meshService.releaseToPoolForPhone(client, p);
    }
    TEST_ASSERT_NULL(meshService.getForPhone(client));
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

// 1b: the only client holding a payload is unregistered while it holds it; its late release must not free it again.
void test_single_client_close_then_late_release_is_safe(void)
{
    MeshService meshService;
    DummyClientToken token;
    PhoneAPI *client = asClient(token);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client, MeshService::STATE_BLE));
    meshService.sendToPhone(allocDecodedPacket(611, 0x6011));
    meshtastic_MeshPacket *held = meshService.getForPhone(client);
    TEST_ASSERT_NOT_NULL(held);

    meshService.unregisterPhoneClient(client);       // last reference: the payload is released here
    meshService.releaseToPoolForPhone(client, held); // no slot any more: must be a no-op, not a second release

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client, MeshService::STATE_BLE));
    TEST_ASSERT_NULL(meshService.getForPhone(client));
    meshService.unregisterPhoneClient(client);
}

// 3: a full queue evicts its oldest non-text packet first; only a queue full of text drops a new non-text packet.
void test_full_queue_evicts_oldest_non_text_first(void)
{
    MeshService meshService;
    DummyClientToken token;
    PhoneAPI *client = asClient(token);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client, MeshService::STATE_PACKET));

    meshService.sendToPhone(allocDecodedPacket(1, NODENUM_BROADCAST)); // text
    for (uint32_t id = 2; id <= MAX_RX_TOPHONE; id++)
        meshService.sendToPhone(allocTelemetryPacket(id));
    meshService.sendToPhone(allocTelemetryPacket(100));                  // evicts 2
    meshService.sendToPhone(allocDecodedPacket(200, NODENUM_BROADCAST)); // evicts 3

    uint32_t expected[MAX_RX_TOPHONE];
    size_t n = 0;
    expected[n++] = 1;
    for (uint32_t id = 4; id <= MAX_RX_TOPHONE; id++)
        expected[n++] = id;
    expected[n++] = 100;
    expected[n++] = 200;
    expectDrainOrder(meshService, client, expected, n);

    for (uint32_t id = 1; id <= MAX_RX_TOPHONE; id++)
        meshService.sendToPhone(allocDecodedPacket(300 + id, NODENUM_BROADCAST));
    meshService.sendToPhone(allocTelemetryPacket(999));                  // queue full of text: dropped
    meshService.sendToPhone(allocDecodedPacket(500, NODENUM_BROADCAST)); // evicts the oldest text, 301
    n = 0;
    for (uint32_t id = 2; id <= MAX_RX_TOPHONE; id++)
        expected[n++] = 300 + id;
    expected[n++] = 500;
    expectDrainOrder(meshService, client, expected, n);
}

// 3: the backlog kept while no client is connected follows the same policy.
void test_full_detached_backlog_evicts_oldest_non_text_first(void)
{
    MeshService meshService;
    meshService.sendToPhone(allocDecodedPacket(1, NODENUM_BROADCAST));
    for (uint32_t id = 2; id <= MAX_RX_TOPHONE; id++)
        meshService.sendToPhone(allocTelemetryPacket(id));
    meshService.sendToPhone(allocTelemetryPacket(100)); // evicts 2

    DummyClientToken token;
    PhoneAPI *client = asClient(token);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client, MeshService::STATE_SERIAL));
    uint32_t expected[MAX_RX_TOPHONE];
    size_t n = 0;
    expected[n++] = 1;
    for (uint32_t id = 3; id <= MAX_RX_TOPHONE; id++)
        expected[n++] = id;
    expected[n++] = 100;
    expectDrainOrder(meshService, client, expected, n);
    meshService.unregisterPhoneClient(client);

    for (uint32_t id = 1; id <= MAX_RX_TOPHONE; id++)
        meshService.sendToPhone(allocDecodedPacket(300 + id, NODENUM_BROADCAST));
    meshService.sendToPhone(allocTelemetryPacket(999)); // backlog full of text: dropped
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(client, MeshService::STATE_SERIAL));
    n = 0;
    for (uint32_t id = 1; id <= MAX_RX_TOPHONE; id++)
        expected[n++] = 300 + id;
    expectDrainOrder(meshService, client, expected, n);
}

// 3: a client that stops reading is suspended and its queue released, so it cannot pin payloads; it resumes as soon as
// it reads again. A client that keeps reading (e.g. a long config download) is never suspended.
void test_stale_client_suspended_and_released_until_it_reads(void)
{
    MeshService meshService;
    DummyClientToken liveToken, stuckToken;
    PhoneAPI *live = asClient(liveToken);
    PhoneAPI *stuck = asClient(stuckToken);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(live, MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(stuck, MeshService::STATE_PACKET));

    const uint32_t first[] = {1};
    meshService.sendToPhone(allocTelemetryPacket(1));
    expectDrainOrder(meshService, live, first, 1);

    // Still reading (config download): not stale even though packets are pending.
    MeshServiceTestAccess::ageClient(meshService, stuck, MeshServiceTestAccess::kStaleMs + 1000);
    meshService.notePhoneClientRead(stuck);
    meshService.sendToPhone(allocTelemetryPacket(2));
    TEST_ASSERT_FALSE(MeshServiceTestAccess::isSuspended(meshService, stuck));

    // Stops reading: the next packet suspends it and releases its queue.
    MeshServiceTestAccess::ageClient(meshService, stuck, MeshServiceTestAccess::kStaleMs + 1000);
    meshService.sendToPhone(allocTelemetryPacket(3));
    TEST_ASSERT_TRUE(MeshServiceTestAccess::isSuspended(meshService, stuck));
    meshService.sendToPhone(allocTelemetryPacket(4));
    const uint32_t liveRest[] = {2, 3, 4};
    expectDrainOrder(meshService, live, liveRest, 3);

    // A suspended client neither blocks store-and-forward nor keeps the node awake.
    TEST_ASSERT_TRUE(meshService.canAcceptStoreForwardPacket());
    TEST_ASSERT_TRUE(meshService.isToPhoneQueueEmpty());

    // Reading again resumes it with new traffic only.
    TEST_ASSERT_NULL(meshService.getForPhone(stuck));
    TEST_ASSERT_FALSE(MeshServiceTestAccess::isSuspended(meshService, stuck));
    meshService.sendToPhone(allocTelemetryPacket(5));
    const uint32_t fifth[] = {5};
    expectDrainOrder(meshService, stuck, fifth, 1);
    expectDrainOrder(meshService, live, fifth, 1);
}

// 6: what one client sends reaches the other clients (touchscreen <-> phone), never the sender itself.
void test_client_sent_packet_reaches_other_clients_only(void)
{
    MeshService meshService;
    DummyClientToken uiToken, phoneToken, serialToken;
    PhoneAPI *ui = asClient(uiToken);
    PhoneAPI *phone = asClient(phoneToken);
    PhoneAPI *serial = asClient(serialToken);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(ui, MeshService::STATE_PACKET));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(phone, MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(serial, MeshService::STATE_SERIAL));

    meshService.sendToOtherPhones(allocDecodedPacket(1201, NODENUM_BROADCAST), phone);
    const uint32_t ids[] = {1201};
    expectDrainOrder(meshService, ui, ids, 1);
    expectDrainOrder(meshService, serial, ids, 1);
    TEST_ASSERT_NULL(meshService.getForPhone(phone));

    // Only the sender connected: nothing is queued, nothing leaks into the detached backlog.
    meshService.unregisterPhoneClient(ui);
    meshService.unregisterPhoneClient(serial);
    meshService.sendToOtherPhones(allocDecodedPacket(1202, NODENUM_BROADCAST), phone);
    TEST_ASSERT_NULL(meshService.getForPhone(phone));
    meshService.unregisterPhoneClient(phone);
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(ui, MeshService::STATE_PACKET));
    TEST_ASSERT_NULL(meshService.getForPhone(ui));

    // Chat-like packets are shared; admin and other app traffic is not.
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p.decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    TEST_ASSERT_TRUE(MeshService::isSharedWithOtherClients(&p));
    p.decoded.portnum = meshtastic_PortNum_WAYPOINT_APP;
    TEST_ASSERT_TRUE(MeshService::isSharedWithOtherClients(&p));
    p.decoded.portnum = meshtastic_PortNum_ADMIN_APP;
    TEST_ASSERT_FALSE(MeshService::isSharedWithOtherClients(&p));
    p.decoded.portnum = meshtastic_PortNum_POSITION_APP;
    TEST_ASSERT_FALSE(MeshService::isSharedWithOtherClients(&p));
}

// Consumes a SessionHandoffQueue exactly like BluetoothPhoneAPI::runOnceHandleFromPhoneQueue does on the main task.
class HandoffTestPhoneAPI : public PhoneAPI
{
  public:
    HandoffTestPhoneAPI() { api_type = TYPE_BLE; }
    SessionHandoffQueue<std::vector<uint8_t>, 4> fromPhone;
    int closes = 0;

    void writeWantConfig(uint32_t nonce)
    {
        meshtastic_ToRadio tr = meshtastic_ToRadio_init_zero;
        tr.which_payload_variant = meshtastic_ToRadio_want_config_id_tag;
        tr.want_config_id = nonce;
        std::vector<uint8_t> buf(meshtastic_ToRadio_size);
        buf.resize(pb_encode_to_bytes(buf.data(), buf.size(), &meshtastic_ToRadio_msg, &tr));
        TEST_ASSERT_TRUE(fromPhone.push(buf));
    }
    void runOnce()
    {
        std::vector<uint8_t> val;
        auto popped = fromPhone.pop(val);
        if (popped.closeFirst) {
            closes++;
            close();
        }
        if (popped.havePacket)
            handleToRadio(val.data(), val.size());
    }

  protected:
    bool checkIsConnected() override { return true; }
};

// 5: BLE disconnect, reconnect and want_config written before the main task ran: the old session is closed first (its
// queued packets dropped), then the new session starts clean.
void test_ble_reconnect_before_runonce_closes_old_session_first(void)
{
    MeshService meshService;
    MeshService *previousService = service;
    service = &meshService;

    {
        HandoffTestPhoneAPI ble;
        ble.writeWantConfig(1);
        ble.runOnce();
        TEST_ASSERT_TRUE(ble.isConnected());
        meshService.sendToPhone(allocDecodedPacket(1301, NODENUM_BROADCAST)); // queued for the old session

        ble.fromPhone.disconnect(); // NimBLE task
        ble.writeWantConfig(2);     // new connection, before the main task ran
        TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)ble.fromPhone.size());

        ble.runOnce();
        TEST_ASSERT_EQUAL(1, ble.closes);
        TEST_ASSERT_TRUE(ble.isConnected());
        TEST_ASSERT_NULL(meshService.getForPhone(&ble)); // old session's packet did not leak into the new one
        TEST_ASSERT_FALSE(ble.fromPhone.takePendingClose());

        // Disconnect without reconnect: the close is handed over exactly once.
        ble.fromPhone.disconnect();
        TEST_ASSERT_TRUE(ble.fromPhone.takePendingClose());
        TEST_ASSERT_FALSE(ble.fromPhone.takePendingClose());
    }

    TEST_ASSERT_EQUAL_UINT32(0u, meshService.api_state_mask);
    service = previousService;
}

// 5: writes beyond the queue depth are refused, not overwritten, and the disconnect drops queued writes.
void test_session_handoff_queue_bounds_and_disconnect(void)
{
    SessionHandoffQueue<int, 2> q;
    TEST_ASSERT_TRUE(q.push(1));
    TEST_ASSERT_TRUE(q.push(2));
    TEST_ASSERT_FALSE(q.push(3));
    int v = 0;
    auto r = q.pop(v);
    TEST_ASSERT_FALSE(r.closeFirst);
    TEST_ASSERT_TRUE(r.havePacket);
    TEST_ASSERT_EQUAL(1, v);

    q.disconnect();
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)q.size());
    r = q.pop(v);
    TEST_ASSERT_TRUE(r.closeFirst);
    TEST_ASSERT_FALSE(r.havePacket);
    r = q.pop(v);
    TEST_ASSERT_FALSE(r.closeFirst);
}

// Multi-BLE: each connection handle gets its own slot, a full table refuses further centrals, a freed slot is reused,
// and readers never claim. A limit of 1 keeps the single-central behaviour.
void test_ble_slot_table_claim_release_and_limit(void)
{
    BleSlotTable<3> t;
    TEST_ASSERT_EQUAL_UINT32(0u, (uint32_t)t.count());
    TEST_ASSERT_EQUAL_UINT16(BleSlotTable<3>::kNoHandle, t.firstConnectedHandle());

    TEST_ASSERT_EQUAL_INT(0, t.claim(5));
    TEST_ASSERT_EQUAL_INT(1, t.claim(7));
    TEST_ASSERT_EQUAL_INT(0, t.claim(5)); // same handle, same slot
    TEST_ASSERT_EQUAL_INT(2, t.claim(9));
    TEST_ASSERT_TRUE(t.full());
    TEST_ASSERT_EQUAL_INT(-1, t.claim(11));

    TEST_ASSERT_EQUAL_INT(1, t.release(7));
    TEST_ASSERT_EQUAL_INT(-1, t.find(7));
    TEST_ASSERT_EQUAL_INT(-1, t.release(7)); // released once
    TEST_ASSERT_FALSE(t.full());
    TEST_ASSERT_EQUAL_INT(1, t.claim(11));
    TEST_ASSERT_EQUAL_UINT16(5, t.firstConnectedHandle());
    TEST_ASSERT_EQUAL_INT(-1, t.claim(BleSlotTable<3>::kNoHandle));

    BleSlotTable<3> single;
    single.setLimit(1);
    TEST_ASSERT_EQUAL_INT(0, single.claim(1));
    TEST_ASSERT_TRUE(single.full());
    TEST_ASSERT_EQUAL_INT(-1, single.claim(2));
    single.setLimit(0);
    TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)single.usable());
    single.setLimit(9);
    TEST_ASSERT_EQUAL_UINT32(3u, (uint32_t)single.usable());
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

static int drainConfigSync(MeshService &meshService, PhoneAPI *client, MeshService::ConfigSyncItem *items, int maxItems)
{
    int n = 0;
    MeshService::ConfigSyncItem item;
    while (n < maxItems && meshService.takePendingConfigForPhone(client, item)) {
        items[n++] = item;
    }
    return n;
}

void test_config_sync_skips_requester_and_reaches_other_clients(void)
{
    MeshService meshService;
    DummyClientToken t1, t2, t3;
    PhoneAPI *mui = asClient(t1);
    PhoneAPI *ble = asClient(t2);
    PhoneAPI *serial = asClient(t3);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(mui, MeshService::STATE_PACKET));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(ble, MeshService::STATE_BLE));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(serial, MeshService::STATE_SERIAL));

    meshService.noteAdminRequestOrigin(0x1234, mui);

    MeshService::ConfigSyncSet changed;
    changed.config = (1u << meshtastic_Config_bluetooth_tag) | (1u << meshtastic_Config_lora_tag);
    changed.channels = 1u << 2;
    changed.owner = true;
    TEST_ASSERT_EQUAL_INT(2, meshService.pushConfigToOtherPhoneClients(changed, 0x1234));

    TEST_ASSERT_FALSE(meshService.hasPendingConfigForPhone(mui));
    TEST_ASSERT_TRUE(meshService.hasPendingConfigForPhone(ble));
    TEST_ASSERT_TRUE(meshService.hasPendingConfigForPhone(serial));

    PhoneAPI *others[] = {ble, serial};
    for (PhoneAPI *client : others) {
        MeshService::ConfigSyncItem items[8];
        TEST_ASSERT_EQUAL_INT(4, drainConfigSync(meshService, client, items, 8));
        // same order as the initial config download: owner, channels, config (by tag)
        TEST_ASSERT_EQUAL_UINT8(MeshService::ConfigSyncItem::OWNER, items[0].kind);
        TEST_ASSERT_EQUAL_UINT8(MeshService::ConfigSyncItem::CHANNEL, items[1].kind);
        TEST_ASSERT_EQUAL_UINT8(2, items[1].index);
        TEST_ASSERT_EQUAL_UINT8(MeshService::ConfigSyncItem::CONFIG, items[2].kind);
        TEST_ASSERT_EQUAL_UINT8(meshtastic_Config_lora_tag, items[2].index);
        TEST_ASSERT_EQUAL_UINT8(MeshService::ConfigSyncItem::CONFIG, items[3].kind);
        TEST_ASSERT_EQUAL_UINT8(meshtastic_Config_bluetooth_tag, items[3].index);
        TEST_ASSERT_FALSE(meshService.hasPendingConfigForPhone(client));
    }

    MeshService::ConfigSyncItem item;
    TEST_ASSERT_FALSE(meshService.takePendingConfigForPhone(mui, item));
}

void test_config_sync_unknown_requester_reaches_all_and_coalesces(void)
{
    MeshService meshService;
    DummyClientToken t1, t2;
    PhoneAPI *mui = asClient(t1);
    PhoneAPI *ble = asClient(t2);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(mui, MeshService::STATE_PACKET));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(ble, MeshService::STATE_BLE));

    MeshService::ConfigSyncSet changed;
    changed.moduleConfig = 1u << meshtastic_ModuleConfig_mqtt_tag;

    // remote admin (no local requester) and an id we never saw both reach every client
    TEST_ASSERT_EQUAL_INT(2, meshService.pushConfigToOtherPhoneClients(changed, 0));
    TEST_ASSERT_EQUAL_INT(2, meshService.pushConfigToOtherPhoneClients(changed, 0xBEEF));

    PhoneAPI *clients[] = {mui, ble};
    for (PhoneAPI *client : clients) {
        MeshService::ConfigSyncItem items[4];
        // repeated changes of one section coalesce into a single re-send
        TEST_ASSERT_EQUAL_INT(1, drainConfigSync(meshService, client, items, 4));
        TEST_ASSERT_EQUAL_UINT8(MeshService::ConfigSyncItem::MODULE_CONFIG, items[0].kind);
        TEST_ASSERT_EQUAL_UINT8(meshtastic_ModuleConfig_mqtt_tag, items[0].index);
    }

    MeshService::ConfigSyncSet nothing;
    TEST_ASSERT_EQUAL_INT(0, meshService.pushConfigToOtherPhoneClients(nothing, 0));
}

void test_config_sync_cleared_on_unregister(void)
{
    MeshService meshService;
    DummyClientToken t1, t2;
    PhoneAPI *mui = asClient(t1);
    PhoneAPI *ble = asClient(t2);

    TEST_ASSERT_TRUE(meshService.registerPhoneClient(mui, MeshService::STATE_PACKET));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(ble, MeshService::STATE_BLE));

    MeshService::ConfigSyncSet changed;
    changed.config = 1u << meshtastic_Config_device_tag;
    meshService.noteAdminRequestOrigin(42, mui);
    TEST_ASSERT_EQUAL_INT(1, meshService.pushConfigToOtherPhoneClients(changed, 42));
    TEST_ASSERT_TRUE(meshService.hasPendingConfigForPhone(ble));

    // a client that disconnects drops its pending sections; a fresh connection downloads the full config anyway
    meshService.unregisterPhoneClient(ble);
    TEST_ASSERT_FALSE(meshService.hasPendingConfigForPhone(ble));
    TEST_ASSERT_TRUE(meshService.registerPhoneClient(ble, MeshService::STATE_BLE));
    TEST_ASSERT_FALSE(meshService.hasPendingConfigForPhone(ble));
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
    RUN_TEST(test_single_client_close_then_late_release_is_safe);
    RUN_TEST(test_full_queue_evicts_oldest_non_text_first);
    RUN_TEST(test_full_detached_backlog_evicts_oldest_non_text_first);
    RUN_TEST(test_stale_client_suspended_and_released_until_it_reads);
    RUN_TEST(test_client_sent_packet_reaches_other_clients_only);
    RUN_TEST(test_ble_reconnect_before_runonce_closes_old_session_first);
    RUN_TEST(test_session_handoff_queue_bounds_and_disconnect);
    RUN_TEST(test_ble_slot_table_claim_release_and_limit);
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
    RUN_TEST(test_config_sync_skips_requester_and_reaches_other_clients);
    RUN_TEST(test_config_sync_unknown_requester_reaches_all_and_coalesces);
    RUN_TEST(test_config_sync_cleared_on_unregister);
    exit(UNITY_END());
}

void loop() {}
