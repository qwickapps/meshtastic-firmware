/**
 * Config coherence end to end: a local admin request sent by one phone client goes MeshService::handleToRadio ->
 * Router -> AdminModule, and every *other* phone client then gets the changed section from PhoneAPI::getFromRadio,
 * ahead of the mesh packets already queued for it. Also covers the edit transaction (begin/commit) and its ownership.
 */
#include "MeshService.h"
#include "NodeDB.h"
#include "PhoneAPI.h"
#include "Router.h"
#include "SPILock.h"
#include "TestUtil.h"
#include "main.h"
#include "mesh-pb-constants.h"
#include "modules/AdminModule.h"
#include <unity.h>

#if !MESHTASTIC_EXCLUDE_ADMIN

namespace
{

/// Delivers packets addressed to us to the modules right away (the real Router runs its queue on its own thread)
class TestRouter : public Router
{
  public:
    void enqueueReceivedMessage(meshtastic_MeshPacket *p) override
    {
        Router::enqueueReceivedMessage(p);
        runOnce();
    }
};

/// Phone client with an always-up link, driven by the test
class TestPhoneAPI : public PhoneAPI
{
  public:
    explicit TestPhoneAPI(bool ble) { api_type = ble ? TYPE_BLE : TYPE_SERIAL; }

    /// Register with the service and download the full config, like a client that just connected
    void connect()
    {
        handleStartConfig();
        uint8_t buf[MAX_TO_FROM_RADIO_SIZE];
        for (int i = 0; i < 1000 && !isSendingPackets(); i++)
            getFromRadio(buf);
        TEST_ASSERT_TRUE(isSendingPackets());
    }

    /// Next FromRadio for this client (queue status updates skipped); false if there is none
    bool next(meshtastic_FromRadio &out)
    {
        uint8_t buf[MAX_TO_FROM_RADIO_SIZE];
        for (;;) {
            size_t n = getFromRadio(buf);
            if (n == 0)
                return false;
            out = meshtastic_FromRadio_init_zero;
            TEST_ASSERT_TRUE(pb_decode_from_bytes(buf, n, &meshtastic_FromRadio_msg, &out));
            if (out.which_payload_variant != meshtastic_FromRadio_queueStatus_tag)
                return true;
        }
    }

    void drain()
    {
        meshtastic_FromRadio fr;
        while (next(fr)) {
        }
    }

  protected:
    bool checkIsConnected() override { return true; }
};

AdminModule *admin;

/// Send a local admin request as phone client `from` would: through MeshService::handleToRadio
void sendAdmin(PhoneAPI *from, const meshtastic_AdminMessage &msg)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.to = nodeDB->getNodeNum();
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p.decoded.portnum = meshtastic_PortNum_ADMIN_APP;
    p.decoded.payload.size =
        pb_encode_to_bytes(p.decoded.payload.bytes, sizeof(p.decoded.payload.bytes), &meshtastic_AdminMessage_msg, &msg);
    service->handleToRadio(p, from);
}

meshtastic_AdminMessage setPowerConfig()
{
    meshtastic_AdminMessage msg = meshtastic_AdminMessage_init_zero;
    msg.which_payload_variant = meshtastic_AdminMessage_set_config_tag;
    msg.set_config.which_payload_variant = meshtastic_Config_power_tag;
    msg.set_config.payload_variant.power = config.power; // unchanged values: no reboot needed
    return msg;
}

meshtastic_AdminMessage setChannel(uint8_t index)
{
    meshtastic_AdminMessage msg = meshtastic_AdminMessage_init_zero;
    msg.which_payload_variant = meshtastic_AdminMessage_set_channel_tag;
    msg.set_channel = channels.getByIndex(index);
    msg.set_channel.index = index;
    return msg;
}

meshtastic_AdminMessage transaction(pb_size_t tag)
{
    meshtastic_AdminMessage msg = meshtastic_AdminMessage_init_zero;
    msg.which_payload_variant = tag;
    if (tag == meshtastic_AdminMessage_begin_edit_settings_tag)
        msg.begin_edit_settings = true;
    else
        msg.commit_edit_settings = true;
    return msg;
}

/// A mesh packet for the phones, as if just received from the radio
void queueMeshPacket(PacketId id)
{
    meshtastic_MeshPacket *p = packetPool.allocZeroed();
    p->id = id;
    p->from = 0x0badcafe;
    p->to = NODENUM_BROADCAST;
    p->which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p->decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    service->sendToPhone(p);
}

void assertNextIsPowerConfig(TestPhoneAPI &api)
{
    meshtastic_FromRadio fr;
    TEST_ASSERT_TRUE(api.next(fr));
    TEST_ASSERT_EQUAL(meshtastic_FromRadio_config_tag, fr.which_payload_variant);
    TEST_ASSERT_EQUAL(meshtastic_Config_power_tag, fr.config.which_payload_variant);
}

void assertNextIsPacket(TestPhoneAPI &api, PacketId id)
{
    meshtastic_FromRadio fr;
    TEST_ASSERT_TRUE(api.next(fr));
    TEST_ASSERT_EQUAL(meshtastic_FromRadio_packet_tag, fr.which_payload_variant);
    TEST_ASSERT_EQUAL_UINT32(id, fr.packet.id);
}

void assertNothingMore(TestPhoneAPI &api)
{
    meshtastic_FromRadio fr;
    TEST_ASSERT_FALSE(api.next(fr));
}

void test_set_config_reaches_other_client_before_queued_packet(void)
{
    TestPhoneAPI a(false), b(true);
    a.connect();
    b.connect();
    a.drain();
    b.drain();

    queueMeshPacket(0x1001);
    sendAdmin(&a, setPowerConfig());

    // b: the changed section first, then the mesh packet that was already queued
    assertNextIsPowerConfig(b);
    assertNextIsPacket(b, 0x1001);
    assertNothingMore(b);

    // a sent the change and knows it: it only gets the mesh packet
    assertNextIsPacket(a, 0x1001);
    assertNothingMore(a);
}

void test_set_channel_reaches_other_client_only(void)
{
    TestPhoneAPI a(false), b(true);
    a.connect();
    b.connect();
    a.drain();
    b.drain();

    sendAdmin(&b, setChannel(1));

    meshtastic_FromRadio fr;
    TEST_ASSERT_TRUE(a.next(fr));
    TEST_ASSERT_EQUAL(meshtastic_FromRadio_channel_tag, fr.which_payload_variant);
    TEST_ASSERT_EQUAL(1, fr.channel.index);
    assertNothingMore(a);
    assertNothingMore(b);
}

void test_edit_transaction_defers_push_until_commit(void)
{
    TestPhoneAPI a(false), b(true);
    a.connect();
    b.connect();
    a.drain();
    b.drain();

    sendAdmin(&b, transaction(meshtastic_AdminMessage_begin_edit_settings_tag));
    sendAdmin(&b, setPowerConfig());
    assertNothingMore(a); // not committed yet

    sendAdmin(&b, transaction(meshtastic_AdminMessage_commit_edit_settings_tag));
    assertNextIsPowerConfig(a);
    assertNothingMore(a);
    assertNothingMore(b);
}

void test_other_client_change_is_not_deferred_by_open_transaction(void)
{
    TestPhoneAPI mui(false), ble(true);
    mui.connect();
    ble.connect();
    mui.drain();
    ble.drain();

    sendAdmin(&ble, transaction(meshtastic_AdminMessage_begin_edit_settings_tag));

    // the MUI changes a setting while the BLE app has its transaction open: pushed to the app right away
    sendAdmin(&mui, setPowerConfig());
    assertNextIsPowerConfig(ble);
    assertNothingMore(mui);

    // the app's own changes are still deferred until it commits
    sendAdmin(&ble, setChannel(2));
    assertNothingMore(mui);
    sendAdmin(&ble, transaction(meshtastic_AdminMessage_commit_edit_settings_tag));
    meshtastic_FromRadio fr;
    TEST_ASSERT_TRUE(mui.next(fr));
    TEST_ASSERT_EQUAL(meshtastic_FromRadio_channel_tag, fr.which_payload_variant);
    TEST_ASSERT_EQUAL(2, fr.channel.index);
}

void test_transaction_aborted_when_owner_disconnects(void)
{
    TestPhoneAPI mui(false);
    mui.connect();
    mui.drain();
    {
        TestPhoneAPI ble(true);
        ble.connect();
        ble.drain();
        sendAdmin(&ble, transaction(meshtastic_AdminMessage_begin_edit_settings_tag));
        sendAdmin(&ble, setPowerConfig());
        TEST_ASSERT_EQUAL_UINT32(0, rebootAtMsec);
    } // the app disconnects without committing

    // main loop: the transaction is aborted and the uncommitted (RAM only) edits are dropped by a reboot
    admin->checkEditTransactionOwner();
    TEST_ASSERT_NOT_EQUAL(0, rebootAtMsec);
    rebootAtMsec = 0;

    // nothing of the aborted transaction is pushed, and changes are no longer deferred
    assertNothingMore(mui);
    TestPhoneAPI ble2(true);
    ble2.connect();
    ble2.drain();
    sendAdmin(&ble2, setPowerConfig());
    assertNextIsPowerConfig(mui);
}

void test_transaction_aborted_when_owner_reconnects(void)
{
    TestPhoneAPI mui(false), ble(true);
    mui.connect();
    ble.connect();
    mui.drain();
    ble.drain();

    sendAdmin(&ble, transaction(meshtastic_AdminMessage_begin_edit_settings_tag));

    // the same PhoneAPI object (as the BLE one is) reconnects: a new connection, the old transaction is gone
    ble.close();
    ble.connect();
    ble.drain();
    admin->checkEditTransactionOwner();
    TEST_ASSERT_EQUAL_UINT32(0, rebootAtMsec); // nothing was changed inside it: no reboot needed

    sendAdmin(&ble, setPowerConfig());
    assertNextIsPowerConfig(mui); // not deferred any more
}

} // namespace

void setUp(void)
{
    service = new MeshService();
    admin = adminModule = new AdminModule();
    rebootAtMsec = 0;
}

void tearDown(void)
{
    delete admin;
    admin = adminModule = nullptr;
    delete service;
    service = nullptr;
    rebootAtMsec = 0;
}

void setup()
{
    initializeTestEnvironment();
    if (!spiLock)
        initSPI();
    nodeDB = new NodeDB();
    router = new TestRouter();

    UNITY_BEGIN();
    RUN_TEST(test_set_config_reaches_other_client_before_queued_packet);
    RUN_TEST(test_set_channel_reaches_other_client_only);
    RUN_TEST(test_edit_transaction_defers_push_until_commit);
    RUN_TEST(test_other_client_change_is_not_deferred_by_open_transaction);
    RUN_TEST(test_transaction_aborted_when_owner_disconnects);
    RUN_TEST(test_transaction_aborted_when_owner_reconnects);
    exit(UNITY_END());
}

#else

void setUp(void) {}
void tearDown(void) {}
void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    exit(UNITY_END());
}

#endif

void loop() {}
