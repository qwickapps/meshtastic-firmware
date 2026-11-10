#include "configuration.h"
#if !MESHTASTIC_EXCLUDE_BLUETOOTH
#include "BluetoothCommon.h"
#include "NimbleBluetooth.h"
#include "PowerFSM.h"
#include "StaticPointerQueue.h"

#include "concurrency/OSThread.h"
#include "main.h"
#include "mesh/BlePairingPinOwner.h"
#include "mesh/BleSlotTable.h"
#include "mesh/PhoneAPI.h"
#include "mesh/SessionHandoffQueue.h"
#include "mesh/mesh-pb-constants.h"
#include "sleep.h"
#include <NimBLEDevice.h>
#include <atomic>
#include <mutex>

#ifdef NIMBLE_TWO
#include "NimBLEAdvertising.h"
#include "NimBLEExtAdvertising.h"
#include "PowerStatus.h"
#endif

#if defined(CONFIG_NIMBLE_CPP_IDF)
#include "host/ble_gap.h"
#else
#include "nimble/nimble/host/include/host/ble_gap.h"
#endif

#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C6)

namespace
{
constexpr uint16_t kPreferredBleMtu = 517;
constexpr uint16_t kPreferredBleTxOctets = 251;
constexpr uint16_t kPreferredBleTxTimeUs = (kPreferredBleTxOctets + 14) * 8;
} // namespace
#endif

// Debugging options: careful, they slow things down quite a bit!
// #define DEBUG_NIMBLE_ON_READ_TIMING  // uncomment to time onRead duration
// #define DEBUG_NIMBLE_ON_WRITE_TIMING // uncomment to time onWrite duration
// #define DEBUG_NIMBLE_NOTIFY          // uncomment to enable notify logging

#define NIMBLE_BLUETOOTH_TO_PHONE_QUEUE_SIZE 3
#define NIMBLE_BLUETOOTH_FROM_PHONE_QUEUE_SIZE 3

/*
  MULTIPLE CENTRALS:
    Up to MAX_BLE_PHONE_CLIENTS centrals (phone, tablet, watch) can be connected at once. Each connection gets a slot in
    bleSlots and its own BluetoothPhoneAPI (registered as a separate MeshService fan-out client), with its own ToRadio /
    FromRadio queues, fromNum notify state, duplicate filter and deferred close. Only the NimBLE host task claims or releases
    a slot (GAP connect / disconnect); the main task only reads the table. Advertising resumes after a connect while slots
    remain. With one central connected, behaviour is the same as the single-connection design.
*/
#ifndef MAX_BLE_PHONE_CLIENTS
#define MAX_BLE_PHONE_CLIENTS 1
#endif
#if MAX_BLE_PHONE_CLIENTS < 1
#error "MAX_BLE_PHONE_CLIENTS must be at least 1"
#endif
#if MAX_BLE_PHONE_CLIENTS > 1 && defined(NIMBLE_TWO)
#error "MAX_BLE_PHONE_CLIENTS > 1 needs the NimBLE-Arduino 1.x per-connection long-read guard (see FromRadio long reads)"
#endif
#if !defined(NIMBLE_TWO) && defined(CONFIG_BT_NIMBLE_MAX_CONNECTIONS)
static_assert(MAX_BLE_PHONE_CLIENTS <= CONFIG_BT_NIMBLE_MAX_CONNECTIONS,
              "MAX_BLE_PHONE_CLIENTS exceeds the NimBLE connection limit (CONFIG_BT_NIMBLE_MAX_CONNECTIONS)");
#endif

NimBLECharacteristic *fromNumCharacteristic;
NimBLECharacteristic *BatteryCharacteristic;
NimBLECharacteristic *logRadioCharacteristic;
NimBLEServer *bleServer;

// The pairing PIN on screen and the connection it belongs to (NimBLE host task only).
static BlePairingPinOwner pairingPin;

// Connection handle -> client slot. Claimed / released only on the NimBLE host task; other tasks only read it.
static BleSlotTable<MAX_BLE_PHONE_CLIENTS> bleSlots;

// CCCD "notifications enabled" bit, as NimBLE reports it to onSubscribe.
constexpr uint16_t kSubscribedNotify = 0x0001;

#ifndef NIMBLE_TWO
/// Main task. NimBLECharacteristic::notify() walks a subscriber vector the host task edits on every (un)subscribe and
/// disconnect; notify one connection directly instead, with the same subscription and encryption checks.
static void notifyConn(NimBLECharacteristic *chr, uint16_t conn_handle, uint16_t subscription, const uint8_t *val, size_t len)
{
    if (!(subscription & kSubscribedNotify))
        return;

    if (chr->getProperties() & (BLE_GATT_CHR_F_READ_AUTHEN | BLE_GATT_CHR_F_READ_AUTHOR | BLE_GATT_CHR_F_READ_ENC)) {
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(conn_handle, &desc) != 0 || !desc.sec_state.encrypted)
            return;
    }

    os_mbuf *om = ble_hs_mbuf_from_flat(val, len);
    if (!om)
        return;
    // ble_gattc_notify_custom always consumes om.
    int rc = ble_gattc_notify_custom(conn_handle, chr->getHandle(), om);
    if (rc != 0)
        LOG_DEBUG("BLE conn %u notify of attr %u failed, rc=%d", conn_handle, chr->getHandle(), rc);
}
#endif

static const char *bleThreadName(uint8_t slot)
{
    // Slot 0 keeps the historical thread name.
    static const char *const names[] = {"NimbleBluetooth", "NimbleBluetooth1", "NimbleBluetooth2", "NimbleBluetooth3"};
    return slot < sizeof(names) / sizeof(names[0]) ? names[slot] : "NimbleBluetoothN";
}

/// NimBLE task: `conn` finished authentication or disconnected; take the PIN off screen if it was that connection's.
static void releasePairingDisplay(uint16_t conn)
{
    if (!pairingPin.release(conn)) {
        return;
    }

#if HAS_SCREEN
    if (screen) {
        screen->endAlert();
    }
#endif
}

class BluetoothPhoneAPI : public PhoneAPI, public concurrency::OSThread
{
    /*
      CAUTION: There's a lot going on here and lots of room to break things.

      This NimbleBluetooth.cpp file does some tricky synchronization between the NimBLE FreeRTOS task (which runs the onRead and
      onWrite callbacks) and the main task (which runs runOnce and the rest of PhoneAPI).

      The main idea is to add a little bit of synchronization here to make it so that the rest of the codebase doesn't have to
      know about concurrency and mutexes, and can just run happily ever after as a cooperative multitasking OSThread system, where
      locking isn't something that anyone has to worry about too much! :)

      We achieve this by having some queues and mutexes in this file only, and ensuring that all calls to getFromRadio and
      handleToRadio are only made from the main FreeRTOS task. This way, the rest of the codebase doesn't have to worry about
      being run concurrently, which would make everything else much much much more complicated.

      PHONE -> RADIO:
        - [NimBLE FreeRTOS task:] onWrite callback pushes received packets into fromPhone (SessionHandoffQueue, own mutex).
        - [Main task:] runOnceHandleFromPhoneQueue in main task pops packets from fromPhone and calls handleToRadio **in main
      task**.

      RADIO -> PHONE:
        - [NimBLE FreeRTOS task:] onRead callback sets onReadCallbackIsWaitingForData flag and polls in a busy loop. (unless
      there's already a packet waiting in toPhoneQueue)
        - [Main task:] runOnceHandleToPhoneQueue sees onReadCallbackIsWaitingForData flag, calls getFromRadio **in main task** to
      get packets from radio, holds toPhoneMutex, pushes the packet into toPhoneQueue, and clears the
      onReadCallbackIsWaitingForData flag.
        - [NimBLE FreeRTOS task:] onRead callback sees that the onReadCallbackIsWaitingForData flag cleared, holds toPhoneMutex,
      pops the packet from toPhoneQueue, and returns it to NimBLE.

      MUTEXES:
        - fromPhone has its own mutex (see SessionHandoffQueue)
        - toPhoneMutex protects toPhoneQueue, toPhoneQueueByteSizes, and toPhoneQueueSize

      DISCONNECT:
        - [NimBLE FreeRTOS task:] onDisconnect only clears the transport queues and calls fromPhone.disconnect().
        - [Main task:] runOnce consumes the pending close and calls PhoneAPI::close() **in main task**. close() releases the
      fanout packets PhoneAPI holds (packetForPhone etc.) and unregisters from MeshService; doing that from the NimBLE task
      raced getFromRadio() on the main task (use-after-free / double release of packetForPhone).
        - A reconnect can arrive before runOnce runs. SessionHandoffQueue::pop() reports the pending close together with the
      new connection's first ToRadio, so the old session is always closed before that is handled. FromRadio data produced
      for the old session is dropped instead of being pushed to the new connection.

      ATOMICS:
        - fromPhone's size is only increased by onWrite, and only decreased by runOnceHandleFromPhoneQueue (or onDisconnect).
        - toPhoneQueueSize is only increased by runOnceHandleToPhoneQueue, and only decreased by onRead (or onDisconnect).
        - onReadCallbackIsWaitingForData is a flag. It's only set by onRead, and only cleared by runOnceHandleToPhoneQueue (or
      onDisconnect).

      PRELOADING: see comments in runOnceToPhoneCanPreloadNextPacket about when it's safe to preload packets from getFromRadio.

      BLE CONNECTION PARAMS:
        - During config, we request a high-throughput, low-latency BLE connection for speed.
        - After config, we switch to a lower-power BLE connection for steady-state use to extend battery life.

      MEMORY MANAGEMENT:
        - We keep packets on the stack and do not allocate heap.
        - We use std::array for fromPhone and toPhoneQueue to avoid mallocs and frees across FreeRTOS tasks.
        - Yes, we have to do some copy operations on pop because of this, but it's worth it to avoid cross-task memory management.

      NOTIFY IS BROKEN:
        - Adding NIMBLE_PROPERTY::NOTIFY to FromRadioCharacteristic appears to break things. It is NOT backwards compatible.

      ZERO-SIZE READS:
        - Returning a zero-size read from onRead breaks some clients during the config phase. So we have to block onRead until we
      have data.
        - During the STATE_SEND_PACKETS phase, it's totally OK to return zero-size reads, as clients are expected to do reads
      until they get a 0-byte response.

      CROSS-TASK WAKEUP:
        - If you call: bluetoothPhoneAPI->setIntervalFromNow(0); to schedule immediate processing of new data,
        - Then you should also call: concurrency::mainDelay.interrupt(); to wake up the main loop if it's sleeping.
        - Otherwise, you're going to wait ~100ms or so until the main loop wakes up from some other cause.
    */

  public:
    explicit BluetoothPhoneAPI(uint8_t slot) : concurrency::OSThread(bleThreadName(slot)), slot(slot) { api_type = TYPE_BLE; }

    /// Index of this client's slot in bleSlots.
    const uint8_t slot;

    /// Handle of the connection currently in this slot, or BLE_HS_CONN_HANDLE_NONE. Any task.
    uint16_t connHandle() const { return bleSlots.handleAt(slot); }

    /// Last ToRadio value received on this connection (NimBLE task only), to drop duplicate writes.
    uint8_t lastToRadio[MAX_TO_FROM_RADIO_SIZE] = {0};

    /// fromNum CCCD value of this connection (set by the NimBLE task, read by the main task).
    std::atomic<uint16_t> fromNumSubscription{0};
    /// logRadio and battery level CCCD values of this connection (set by the NimBLE task, read by the main task).
    std::atomic<uint16_t> logRadioSubscription{0};
    std::atomic<uint16_t> batterySubscription{0};
    /// Last fromNum value of this client, returned when this connection reads the fromNum characteristic.
    std::atomic<uint32_t> lastFromNum{0};

#if MAX_BLE_PHONE_CLIENTS > 1
    /// The FromRadio value this connection's last read returned, for the follow-up pieces of a long read (see FROMRADIO
    /// LONG READS). NimBLE host task only.
    uint8_t longReadSnapshot[meshtastic_FromRadio_size] = {0};
    uint16_t longReadSnapshotLen = 0;
#endif

    /* Packets from phone (BLE onWrite callback), and the disconnect handoff to the main task (see DISCONNECT) */
    // Array-backed (memcpy) to avoid dynamic memory allocations and frees across FreeRTOS tasks.
    SessionHandoffQueue<NimBLEAttValue, NIMBLE_BLUETOOTH_FROM_PHONE_QUEUE_SIZE> fromPhone;

    /* Packets to phone (BLE onRead callback) */
    std::mutex toPhoneMutex;
    std::atomic<size_t> toPhoneQueueSize{0};
    // We use array here (and pay the cost of memcpy) to avoid dynamic memory allocations and frees across FreeRTOS tasks.
    std::array<std::array<uint8_t, meshtastic_FromRadio_size>, NIMBLE_BLUETOOTH_TO_PHONE_QUEUE_SIZE> toPhoneQueue{};
    std::array<size_t, NIMBLE_BLUETOOTH_TO_PHONE_QUEUE_SIZE> toPhoneQueueByteSizes{};
    // The onReadCallbackIsWaitingForData flag provides synchronization between the NimBLE task's onRead callback and our main
    // task's runOnce. It's only set by onRead, and only cleared by runOnce.
    std::atomic<bool> onReadCallbackIsWaitingForData{false};

    /* Statistics/logging helpers */
    std::atomic<int32_t> readCount{0};
    std::atomic<int32_t> notifyCount{0};
    std::atomic<int32_t> writeCount{0};

  protected:
    virtual int32_t runOnce() override
    {
        while (runOnceHasWorkToDo()) {
            // A disconnect must be fully processed before anything else for this transport.
            runOnceHandlePendingClose();

            /*
              PROCESS fromPhoneQueue BEFORE toPhoneQueue:

              In normal STATE_SEND_PACKETS operation, it's unlikely that we'll have both writes and reads to process at the same
              time, because either onWrite or onRead will trigger this runOnce. And in STATE_SEND_PACKETS, it's generally ok to
              service either the reads or writes first.

              However, during the initial setup wantConfig packet, the clients send a write and immediately send a read, and they
              expect the read will respond to the write. (This also happens when a client goes from STATE_SEND_PACKETS back to
              another wantConfig, like the iOS client does when requesting the nodedb after requesting the main config only.)

              So it's safest to always service writes (fromPhoneQueue) before reads (toPhoneQueue), so that any "synchronous"
              write-then-read sequences from the client work as expected, even if this means we block onRead for a while: this is
              what the client wants!
            */

            // PHONE -> RADIO:
            runOnceHandleFromPhoneQueue(); // pull data from onWrite to handleToRadio

            // RADIO -> PHONE:
            runOnceHandleToPhoneQueue(); // push data from getFromRadio to onRead
        }

        // the run is triggered via NimbleBluetoothToRadioCallback and NimbleBluetoothFromRadioCallback
        return INT32_MAX;
    }

    virtual void onConfigStart() override
    {
        LOG_INFO("BLE onConfigStart");

        // Prefer high throughput during config/setup, at the cost of high power consumption (for a few seconds)
        if (bleServer && isConnected()) {
            uint16_t conn_handle = connHandle();
            if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
                requestHighThroughputConnection(conn_handle);
            }
        }
    }

    virtual void onConfigComplete() override
    {
        LOG_INFO("BLE onConfigComplete");

        // Switch to lower power consumption BLE connection params for steady-state use after config/setup is complete
        if (bleServer && isConnected()) {
            uint16_t conn_handle = connHandle();
            if (conn_handle != BLE_HS_CONN_HANDLE_NONE) {
                requestLowerPowerConnection(conn_handle);
            }
        }
    }

  public:
    /// NimBLE task: this slot's connection is gone. Only clears the transport queues; PhoneAPI::close() runs on the main
    /// task (see DISCONNECT).
    void onTransportDisconnected()
    {
        // Do NOT call close() here: this runs in the NimBLE task while the main task may be inside getFromRadio()
        // holding packetForPhone. Ask the main task to close instead (see DISCONNECT notes in BluetoothPhoneAPI).
        fromPhone.disconnect();

        onReadCallbackIsWaitingForData = false;
        { // scope for toPhoneMutex mutex
            std::lock_guard<std::mutex> guard(toPhoneMutex);
            toPhoneQueueSize = 0;
        }

        readCount = 0;
        notifyCount = 0;
        writeCount = 0;

        // Clear the last ToRadio packet buffer to avoid rejecting first packet from new connection
        memset(lastToRadio, 0, sizeof(lastToRadio));
        fromNumSubscription = 0;
        logRadioSubscription = 0;
        batterySubscription = 0;
#if MAX_BLE_PHONE_CLIENTS > 1
        longReadSnapshotLen = 0;
#endif

        setIntervalFromNow(0);
        concurrency::mainDelay.interrupt(); // wake up main loop if sleeping
    }

  protected:
    bool runOnceHasWorkToDo() { return fromPhone.hasPendingClose() || runOnceHasWorkToPhone() || runOnceHasWorkFromPhone(); }

    /// Main task only: close the PhoneAPI session of a connection that onDisconnect reported.
    void performDeferredClose()
    {
        LOG_INFO("BLE: close phone API session of disconnected client");
        close();
        // Nothing produced for the old session may reach the next connection.
        std::lock_guard<std::mutex> guard(toPhoneMutex);
        toPhoneQueueSize = 0;
    }

    /// Main task only. Returns true if a pending close was performed.
    bool runOnceHandlePendingClose()
    {
        if (!fromPhone.takePendingClose())
            return false;
        performDeferredClose();
        return true;
    }

    bool runOnceHasWorkToPhone() { return onReadCallbackIsWaitingForData || runOnceToPhoneCanPreloadNextPacket(); }

    bool runOnceToPhoneCanPreloadNextPacket()
    {
        /*
         * PRELOADING getFromRadio RESPONSES:
         *
         * It's not safe to preload packets if we're in STATE_SEND_PACKETS, because there may be a while between the time we call
         * getFromRadio and when the client actually reads it. If the connection drops in that time, we might lose that packet
         * forever. In STATE_SEND_PACKETS, if we wait for onRead before we call getFromRadio, we minimize the time window where
         * the client might disconnect before completing the read.
         *
         * However, if we're in the setup states (sending config, nodeinfo, etc), it's safe and beneficial to preload packets into
         * toPhoneQueue because the client will just reconnect after a disconnect, losing nothing.
         */

        if (!isConnected()) {
            return false;
        } else if (isSendingPackets()) {
            // If we're in STATE_SEND_PACKETS, we must wait for onRead before calling getFromRadio.
            return false;
        } else {
            // In other states, we can preload as long as there's space in the toPhoneQueue.
            return toPhoneQueueSize < NIMBLE_BLUETOOTH_TO_PHONE_QUEUE_SIZE;
        }
    }

    void runOnceHandleToPhoneQueue()
    {
        // Stack buffer for getFromRadio packet
        uint8_t fromRadioBytes[meshtastic_FromRadio_size] = {0};
        size_t numBytes = 0;

        runOnceHandlePendingClose();

        if (onReadCallbackIsWaitingForData || runOnceToPhoneCanPreloadNextPacket()) {
            numBytes = getFromRadio(fromRadioBytes);

            if (numBytes == 0) {
                /*
                  Client expected a read, but we have nothing to send.

                  In STATE_SEND_PACKETS, it is 100% OK to return a 0-byte response, as we expect clients to do read beyond
                  notifies regularly, to make sure they have nothing else to read.

                  In other states, this is fine **so long as we've already processed pending onWrites first**, because the client
                  may requesting wantConfig and immediately doing a read.
                */
            } else {
                // Push to toPhoneQueue, protected by toPhoneMutex. Hold the mutex as briefly as possible.
                if (toPhoneQueueSize < NIMBLE_BLUETOOTH_TO_PHONE_QUEUE_SIZE) {
                    // Note: the comparison above is safe without a mutex because we are the only method that *increases*
                    // toPhoneQueueSize. (It's okay if toPhoneQueueSize *decreases* in the NimBLE task meanwhile.)

                    { // scope for toPhoneMutex mutex
                        std::lock_guard<std::mutex> guard(toPhoneMutex);
                        if (fromPhone.hasPendingClose()) {
                            // The client disconnected while we were producing this; it belongs to the old session.
                            numBytes = 0;
                        } else {
                            size_t storeAtIndex = toPhoneQueueSize.load();
                            memcpy(toPhoneQueue[storeAtIndex].data(), fromRadioBytes, numBytes);
                            toPhoneQueueByteSizes[storeAtIndex] = numBytes;
                            toPhoneQueueSize++;
                        }
                    }
#ifdef DEBUG_NIMBLE_ON_READ_TIMING
                    LOG_DEBUG("BLE getFromRadio returned numBytes=%u, pushed toPhoneQueueSize=%u", numBytes,
                              toPhoneQueueSize.load());
#endif
                } else {
                    // Shouldn't happen because the onRead callback shouldn't be waiting if the queue is full!
                    LOG_ERROR("Shouldn't happen! Drop FromRadio packet, toPhoneQueue full (%u bytes)", numBytes);
                }
            }

            // Clear the onReadCallbackIsWaitingForData flag so onRead knows it can proceed.
            onReadCallbackIsWaitingForData = false; // only clear this flag AFTER the push
        }
    }

    bool runOnceHasWorkFromPhone() { return fromPhone.size() > 0; }

    void runOnceHandleFromPhoneQueue()
    {
        // Handle packets we received from onWrite from the phone.
        if (fromPhone.size() > 0 || fromPhone.hasPendingClose()) {
            LOG_DEBUG("NimbleBluetooth: handling ToRadio packet, fromPhoneQueueSize=%u", (unsigned)fromPhone.size());

            // If a disconnect happened, everything still queued belongs to a *new* connection, so the old session is
            // closed before handling it.
            NimBLEAttValue val;
            auto popped = fromPhone.pop(val);
            if (popped.closeFirst)
                performDeferredClose();
            if (popped.havePacket)
                handleToRadio(val.data(), val.length());
        }
    }

    /**
     * Subclasses can use this as a hook to provide custom notifications for their transport (i.e. bluetooth notifies)
     */
    virtual void onNowHasData(uint32_t fromRadioNum)
    {
        PhoneAPI::onNowHasData(fromRadioNum);

#ifdef DEBUG_NIMBLE_NOTIFY

        int currentNotifyCount = notifyCount.fetch_add(1);

        uint8_t cc = bleServer->getConnectedCount();
        // This logging slows things down when there are lots of packets going to the phone, like initial connection:
        LOG_DEBUG("BLE notify(%d) fromNum: %d connections: %d", currentNotifyCount, fromRadioNum, cc);
#endif

        uint8_t val[4];
        put_le32(val, fromRadioNum);
        lastFromNum = fromRadioNum;

        fromNumCharacteristic->setValue(val, sizeof(val));

        // Notify only this client's own connection: another central has its own fromNum.
        const uint16_t conn_handle = connHandle();
        if (conn_handle == BLE_HS_CONN_HANDLE_NONE)
            return;
#ifdef NIMBLE_TWO
        fromNumCharacteristic->notify(val, sizeof(val), conn_handle);
#else
        notifyConn(fromNumCharacteristic, conn_handle, fromNumSubscription.load(), val, sizeof(val));
#endif
    }

    /// Check the current underlying physical link to see if the client is currently connected
    virtual bool checkIsConnected() { return bleServer && connHandle() != BLE_HS_CONN_HANDLE_NONE; }

    void requestHighThroughputConnection(uint16_t conn_handle)
    {
        /* Request a lower-latency, higher-throughput BLE connection.

        This comes at the cost of higher power consumption, so we may want to only use this for initial setup, and then switch to
        a slower mode.

        See https://developer.apple.com/library/archive/qa/qa1931/_index.html for formulas to calculate values, iOS/macOS
        constraints, and recommendations. (Android doesn't have specific constraints, but seems to be compatible with the Apple
        recommendations.)

        Selected settings:
            minInterval (units of 1.25ms): 7.5ms = 6 (lower than the Apple recommended minimum, but allows faster when the client
        supports it.)
            maxInterval (units of 1.25ms): 15ms = 12
            latency: 0 (don't allow peripheral to skip any connection events)
            timeout (units of 10ms): 6 seconds = 600 (supervision timeout)

        These are intentionally aggressive to prioritize speed over power consumption, but are only used for a few seconds at
        setup. Not worth adjusting much.
        */
        LOG_INFO("BLE requestHighThroughputConnection");
        bleServer->updateConnParams(conn_handle, 6, 12, 0, 600);
    }

    void requestLowerPowerConnection(uint16_t conn_handle)
    {
        /* Request a lower power consumption (but higher latency, lower throughput) BLE connection.

        This is suitable for steady-state operation after initial setup is complete.

        See https://developer.apple.com/library/archive/qa/qa1931/_index.html for formulas to calculate values, iOS/macOS
        constraints, and recommendations. (Android doesn't have specific constraints, but seems to be compatible with the Apple
        recommendations.)

        Selected settings:
            minInterval (units of 1.25ms): 30ms = 24
            maxInterval (units of 1.25ms): 50ms = 40
            latency: 2 (allow peripheral to skip up to 2 consecutive connection events to save power)
            timeout (units of 10ms): 6 seconds = 600 (supervision timeout)

        There's an opportunity for tuning here if anyone wants to do some power measurements, but these should allow 10-20 packets
        per second.
        */
        LOG_INFO("BLE requestLowerPowerConnection");
        bleServer->updateConnParams(conn_handle, 24, 40, 2, 600);
    }
};

static BluetoothPhoneAPI *bluetoothPhoneAPIs[MAX_BLE_PHONE_CLIENTS];

/// The client of the connection `conn_handle`, or nullptr if that connection has no slot. Any task.
static BluetoothPhoneAPI *apiForConn(uint16_t conn_handle)
{
    int slot = bleSlots.find(conn_handle);
    return slot >= 0 ? bluetoothPhoneAPIs[slot] : nullptr;
}

#ifndef NIMBLE_TWO
/// Main task: notify every connected client subscribed to `chr` (its CCCD value is `subscription` in BluetoothPhoneAPI).
static void notifyEachConn(NimBLECharacteristic *chr, std::atomic<uint16_t> BluetoothPhoneAPI::*subscription, const uint8_t *val,
                           size_t len)
{
    for (size_t i = 0; i < MAX_BLE_PHONE_CLIENTS; i++) {
        BluetoothPhoneAPI *api = bluetoothPhoneAPIs[i];
        const uint16_t conn_handle = bleSlots.handleAt(i);
        if (api && conn_handle != BLE_HS_CONN_HANDLE_NONE)
            notifyConn(chr, conn_handle, (api->*subscription).load(), val, len);
    }
}
#endif

#if MAX_BLE_PHONE_CLIENTS > 1
/*
  FROMRADIO LONG READS (NimBLE-Arduino 1.4.3):
    A FromRadio value longer than the connection's ATT MTU - 3 is read in pieces (Read, then Read Blob with an offset).
    NimBLECharacteristic::handleGapEvent (NimBLECharacteristic.cpp:283-294) calls onRead only for the first piece and
    answers every follow-up from the characteristic's single shared m_value. With two centrals, a read by B between A's
    pieces replaces m_value, and A silently gets B's bytes spliced into its FromRadio; if B's value fits A's MTU, NimBLE
    even calls onRead for A's follow-up and pops a packet A never receives. Apple centrals often negotiate an MTU below
    the 517 we prefer, so long reads do happen.

    Guard: the FromRadio characteristic's GATT access callback is wrapped. First pieces still go through NimBLE (onRead
    pops the packet; handleRead keeps a copy in that connection's BluetoothPhoneAPI). Follow-up pieces are answered from
    that copy and never touch m_value or onRead. Both paths run only on the NimBLE host task, so the copy needs no lock.
    If the guard cannot be installed, or a read is ever seen bypassing it, the slot limit drops to 1.

    The wrapped callback is reached through the service's ble_gatt_chr_def, which the NimBLE host reads on every access
    (ble_gatts_chr_val_access). NimBLE-Arduino only rebuilds that table when services change after start
    (NimBLEServer::serviceChanged), which this firmware never does.
*/
namespace
{
// Standard explicit-instantiation idiom to read NimBLEService::m_pSvcDef without patching the library.
template <typename Tag, typename Tag::type Member> struct PrivateMemberAccess {
    friend typename Tag::type privateMember(Tag) { return Member; }
};
struct NimBLEServiceSvcDefTag {
    using type = ble_gatt_svc_def *NimBLEService::*;
    friend type privateMember(NimBLEServiceSvcDefTag);
};
template struct PrivateMemberAccess<NimBLEServiceSvcDefTag, &NimBLEService::m_pSvcDef>;
} // namespace

static ble_gatt_access_fn *nimbleFromRadioAccess = nullptr; // NimBLECharacteristic::handleGapEvent
static bool fromRadioReadViaGuard = false;                  // NimBLE host task only

static int fromRadioAccessGuard(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    // Same follow-up test NimBLE itself uses (NimBLECharacteristic.cpp:285): a read at an offset gets a fresh mbuf whose
    // packet header carries no user header (8 bytes), a first read gets the ATT response mbuf.
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR && !(ctxt->om->om_pkthdr_len > 8)) {
        BluetoothPhoneAPI *api = apiForConn(conn_handle);
        if (!api)
            return BLE_ATT_ERR_UNLIKELY;
        // The host trims the leading `offset` bytes; an offset past the copy is rejected as BLE_ATT_ERR_INVALID_OFFSET.
        int rc = os_mbuf_append(ctxt->om, api->longReadSnapshot, api->longReadSnapshotLen);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    fromRadioReadViaGuard = true;
    int rc = nimbleFromRadioAccess(conn_handle, attr_handle, ctxt, arg);
    fromRadioReadViaGuard = false;
    return rc;
}

/// Setup, after bleService->start() built the service's GATT table.
static bool installFromRadioLongReadGuard(NimBLEService *service, NimBLECharacteristic *fromRadio)
{
    ble_gatt_svc_def *svc = service->*privateMember(NimBLEServiceSvcDefTag());
    if (!svc || !svc[0].characteristics)
        return false;
    for (const ble_gatt_chr_def *chr = svc[0].characteristics; chr->uuid != nullptr; ++chr) {
        if (chr->arg == fromRadio && chr->access_cb != nullptr) {
            nimbleFromRadioAccess = chr->access_cb;
            // The table is heap memory NimBLEService allocated non-const; the host only sees it through const pointers.
            const_cast<ble_gatt_chr_def *>(chr)->access_cb = fromRadioAccessGuard;
            return true;
        }
    }
    return false;
}

// NimBLE-Arduino 1.4.3 does not tell onPassKeyRequest() which connection it is for: wrap each connection's GAP callback so
// PASSKEY_ACTION records its conn handle while NimBLEServer::handleGapEvent calls onPassKeyRequest (same host task).
namespace
{
struct NimBLEServerGapEventTag {
    using type = int (*)(struct ble_gap_event *, void *);
    friend type privateMember(NimBLEServerGapEventTag);
};
template struct PrivateMemberAccess<NimBLEServerGapEventTag, &NimBLEServer::handleGapEvent>;
} // namespace

static uint16_t passkeyRequestConn = BLE_HS_CONN_HANDLE_NONE; // NimBLE host task only

static int connGapEventWithPasskeyOwner(struct ble_gap_event *event, void *arg)
{
    static const auto nimbleServerGapEvent = privateMember(NimBLEServerGapEventTag());
    if (event->type != BLE_GAP_EVENT_PASSKEY_ACTION)
        return nimbleServerGapEvent(event, arg);
    passkeyRequestConn = event->passkey.conn_handle;
    int rc = nimbleServerGapEvent(event, arg);
    passkeyRequestConn = BLE_HS_CONN_HANDLE_NONE;
    return rc;
}

/// NimBLE task, GAP connect. The advertising instance is the callback argument NimBLE gave the connection.
static void trackPasskeyRequests(uint16_t connHandle)
{
    int rc = ble_gap_set_event_cb(connHandle, connGapEventWithPasskeyOwner, NimBLEDevice::getAdvertising());
    if (rc != 0)
        LOG_WARN("BLE conn %u: cannot track its pairing PIN, rc=%d", connHandle, rc);
}
#endif

/*
  NimBLE-Arduino 1.x DOUBLE DISPATCH:
    NimBLECharacteristic::handleGapEvent (NimBLECharacteristic.cpp:288-289 for reads, :319-320 for writes) calls BOTH
    onRead(chr) and onRead(chr, desc), and both onWrite(chr) and onWrite(chr, desc); NimBLEServer does the same for
    onConnect / onDisconnect (NimBLEServer.cpp:368-369). Override exactly one overload of each (the one that carries the
    connection), never both, or every read pops two FromRadio packets and every write is queued twice.
*/

class NimbleBluetoothToRadioCallback : public NimBLECharacteristicCallbacks
{
#ifdef NIMBLE_TWO
    virtual void onWrite(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo) override
    {
        handleWrite(pCharacteristic, connInfo.getConnHandle());
    }
#else
    virtual void onWrite(NimBLECharacteristic *pCharacteristic, ble_gap_conn_desc *desc) override
    {
        handleWrite(pCharacteristic, desc->conn_handle);
    }
#endif

    void handleWrite(NimBLECharacteristic *pCharacteristic, uint16_t conn_handle)
    {
        // CAUTION: This callback runs in the NimBLE task!!! Don't do anything except communicate with the main task's runOnce.
        // Assumption: onWrite is serialized by NimBLE, so we don't need to lock here against multiple concurrent onWrite calls.

        BluetoothPhoneAPI *bluetoothPhoneAPI = apiForConn(conn_handle);
        if (!bluetoothPhoneAPI) {
            LOG_WARN("BLE onWrite: drop ToRadio from conn %u, which has no client slot", conn_handle);
            return;
        }

        int currentWriteCount = bluetoothPhoneAPI->writeCount.fetch_add(1);

#ifdef DEBUG_NIMBLE_ON_WRITE_TIMING
        int startMillis = millis();
        LOG_DEBUG("BLE onWrite(%d): start millis=%d", currentWriteCount, startMillis);
#endif

        auto val = pCharacteristic->getValue();

        uint8_t *lastToRadio = bluetoothPhoneAPI->lastToRadio;
        if (memcmp(lastToRadio, val.data(), val.length()) != 0) {
            if (bluetoothPhoneAPI->fromPhone.push(val)) {
                memcpy(lastToRadio, val.data(), val.length());

                // Schedule immediate processing of the new packet.
                bluetoothPhoneAPI->setIntervalFromNow(0);
                concurrency::mainDelay.interrupt(); // wake up main loop if sleeping

#ifdef DEBUG_NIMBLE_ON_WRITE_TIMING
                int finishMillis = millis();
                LOG_DEBUG("BLE onWrite(%d): append to fromPhone took %u ms. numBytes=%d", currentWriteCount,
                          finishMillis - startMillis, val.length());
#endif
            } else {
                LOG_WARN("BLE onWrite(%d): Drop ToRadio packet, fromPhone full (%u bytes)", currentWriteCount, val.length());
            }
        } else {
            LOG_DEBUG("BLE onWrite(%d): Drop duplicate ToRadio packet (%u bytes)", currentWriteCount, val.length());
        }
    }
};

class NimbleBluetoothFromRadioCallback : public NimBLECharacteristicCallbacks
{
#ifdef NIMBLE_TWO
    virtual void onRead(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo) override
    {
        handleRead(pCharacteristic, connInfo.getConnHandle());
    }
#else
    virtual void onRead(NimBLECharacteristic *pCharacteristic, ble_gap_conn_desc *desc) override
    {
        handleRead(pCharacteristic, desc->conn_handle);
    }
#endif

    void handleRead(NimBLECharacteristic *pCharacteristic, uint16_t conn_handle)
    {
        // CAUTION: This callback runs in the NimBLE task!!! Don't do anything except communicate with the main task's runOnce.

        BluetoothPhoneAPI *bluetoothPhoneAPI = apiForConn(conn_handle);
        if (!bluetoothPhoneAPI) {
            LOG_WARN("BLE onRead: conn %u has no client slot, returning an empty FromRadio", conn_handle);
            uint8_t none = 0;
            pCharacteristic->setValue(&none, 0);
            return;
        }

        int currentReadCount = bluetoothPhoneAPI->readCount.fetch_add(1);
        int tries = 0;
        int startMillis = millis();

#ifdef DEBUG_NIMBLE_ON_READ_TIMING
        LOG_DEBUG("BLE onRead(%d): start millis=%d", currentReadCount, startMillis);
#endif

        // Is there a packet ready to go, or do we have to ask the main task to get one for us?
        if (bluetoothPhoneAPI->toPhoneQueueSize > 0) {
            // Note: the comparison above is safe without a mutex because we are the only method that *decreases*
            // toPhoneQueueSize. (It's okay if toPhoneQueueSize *increases* in the main task meanwhile.)

            // There's already a packet queued. Great! We don't need to wait for onReadCallbackIsWaitingForData.
#ifdef DEBUG_NIMBLE_ON_READ_TIMING
            LOG_DEBUG("BLE onRead(%d): packet already waiting, no need to set onReadCallbackIsWaitingForData", currentReadCount);
#endif
        } else {
            // Tell the main task that we'd like a packet.
            bluetoothPhoneAPI->onReadCallbackIsWaitingForData = true;

            // Wait for the main task to produce a packet for us, up to about 20 seconds.
            // It normally takes just a few milliseconds, but at initial startup, etc, the main task can get blocked for longer
            // doing various setup tasks.
            while (bluetoothPhoneAPI->onReadCallbackIsWaitingForData && tries < 4000) {
                // Schedule the main task runOnce to run ASAP.
                bluetoothPhoneAPI->setIntervalFromNow(0);
                concurrency::mainDelay.interrupt(); // wake up main loop if sleeping

                if (!bluetoothPhoneAPI->onReadCallbackIsWaitingForData) {
                    // we may be able to break even before a delay, if the call to interrupt woke up the main loop and it ran
                    // already
#ifdef DEBUG_NIMBLE_ON_READ_TIMING
                    LOG_DEBUG("BLE onRead(%d): broke before delay after %u ms, %d tries", currentReadCount,
                              millis() - startMillis, tries);
#endif
                    break;
                }

                // This delay happens in the NimBLE FreeRTOS task, which really can't do anything until we get a value back.
                // No harm in polling pretty frequently.
                delay(tries < 20 ? 1 : 5);
                tries++;

                if (tries == 4000) {
                    LOG_WARN(
                        "BLE onRead(%d): timeout waiting for data after %u ms, %d tries, giving up and returning 0-size response",
                        currentReadCount, millis() - startMillis, tries);
                }
            }
        }

        // Pop from toPhoneQueue, protected by toPhoneMutex. Hold the mutex as briefly as possible.
        uint8_t fromRadioBytes[meshtastic_FromRadio_size] = {0}; // Stack buffer for getFromRadio packet
        size_t numBytes = 0;
        { // scope for toPhoneMutex mutex
            std::lock_guard<std::mutex> guard(bluetoothPhoneAPI->toPhoneMutex);
            size_t toPhoneQueueSize = bluetoothPhoneAPI->toPhoneQueueSize.load();
            if (toPhoneQueueSize > 0) {
                // Copy from the front of the toPhoneQueue
                memcpy(fromRadioBytes, bluetoothPhoneAPI->toPhoneQueue[0].data(), bluetoothPhoneAPI->toPhoneQueueByteSizes[0]);
                numBytes = bluetoothPhoneAPI->toPhoneQueueByteSizes[0];

                // Shift the rest of the queue down
                for (uint8_t i = 1; i < toPhoneQueueSize; i++) {
                    memcpy(bluetoothPhoneAPI->toPhoneQueue[i - 1].data(), bluetoothPhoneAPI->toPhoneQueue[i].data(),
                           bluetoothPhoneAPI->toPhoneQueueByteSizes[i]);
                    // The above line is similar to:
                    //   bluetoothPhoneAPI->toPhoneQueue[i - 1] = bluetoothPhoneAPI->toPhoneQueue[i]
                    // but is usually faster because it doesn't have to copy all the trailing bytes beyond
                    // toPhoneQueueByteSizes[i].
                    //
                    // We deliberately use an array here (and pay the CPU cost of some memcpy) to avoid synchronizing dynamic
                    // memory allocations and frees across FreeRTOS tasks.

                    bluetoothPhoneAPI->toPhoneQueueByteSizes[i - 1] = bluetoothPhoneAPI->toPhoneQueueByteSizes[i];
                }

                // Safe decrement due to onDisconnect
                if (bluetoothPhoneAPI->toPhoneQueueSize > 0)
                    bluetoothPhoneAPI->toPhoneQueueSize--;
            } else {
                // nothing in the toPhoneQueue; that's fine, and we'll just have numBytes=0.
            }
        }

#ifdef DEBUG_NIMBLE_ON_READ_TIMING
        int finishMillis = millis();
        LOG_DEBUG("BLE onRead(%d): onReadCallbackIsWaitingForData took %u ms, %d tries. numBytes=%d", currentReadCount,
                  finishMillis - startMillis, tries, numBytes);
#endif

        pCharacteristic->setValue(fromRadioBytes, numBytes);

#if MAX_BLE_PHONE_CLIENTS > 1
        // Follow-up pieces of a long read are answered from this copy (see FROMRADIO LONG READS).
        memcpy(bluetoothPhoneAPI->longReadSnapshot, fromRadioBytes, numBytes);
        bluetoothPhoneAPI->longReadSnapshotLen = numBytes;
        if (!fromRadioReadViaGuard && bleSlots.usable() > 1) {
            LOG_ERROR("BLE FromRadio read bypassed the long-read guard; allowing one central from now on");
            bleSlots.setLimit(1);
        }
#endif

        // If we sent something, wake up the main loop if it's sleeping in case there are more packets ready to enqueue.
        if (numBytes != 0) {
            bluetoothPhoneAPI->setIntervalFromNow(0);
            concurrency::mainDelay.interrupt(); // wake up main loop if sleeping
        }
    }
};

#ifndef NIMBLE_TWO
/// fromNum is per client: each connection reads its own last fromNum, and onNowHasData notifies only its own connection.
class NimbleBluetoothFromNumCallback : public NimBLECharacteristicCallbacks
{
    virtual void onRead(NimBLECharacteristic *pCharacteristic, ble_gap_conn_desc *desc) override
    {
        BluetoothPhoneAPI *api = apiForConn(desc->conn_handle);
        if (!api)
            return;
        uint8_t val[4];
        put_le32(val, api->lastFromNum.load());
        pCharacteristic->setValue(val, sizeof(val));
    }

    virtual void onSubscribe(NimBLECharacteristic *pCharacteristic, ble_gap_conn_desc *desc, uint16_t subValue) override
    {
        BluetoothPhoneAPI *api = apiForConn(desc->conn_handle);
        if (api)
            api->fromNumSubscription = subValue;
    }
};

/// Records a notify-only characteristic's CCCD value per connection, for notifyEachConn.
class NimbleBluetoothSubscriptionCallback : public NimBLECharacteristicCallbacks
{
  public:
    explicit NimbleBluetoothSubscriptionCallback(std::atomic<uint16_t> BluetoothPhoneAPI::*subscription)
        : subscription(subscription)
    {
    }

    virtual void onSubscribe(NimBLECharacteristic *pCharacteristic, ble_gap_conn_desc *desc, uint16_t subValue) override
    {
        BluetoothPhoneAPI *api = apiForConn(desc->conn_handle);
        if (api)
            (api->*subscription) = subValue;
    }

  private:
    std::atomic<uint16_t> BluetoothPhoneAPI::*const subscription;
};
#endif

class NimbleBluetoothServerCallback : public NimBLEServerCallbacks
{
#ifdef NIMBLE_TWO
  public:
    NimbleBluetoothServerCallback(NimbleBluetooth *ble) { this->ble = ble; }

  private:
    NimbleBluetooth *ble;

    virtual uint32_t onPassKeyDisplay()
#else
    virtual uint32_t onPassKeyRequest()
#endif
    {
        uint32_t passkey = config.bluetooth.fixed_pin;
#if MAX_BLE_PHONE_CLIENTS > 1
        const uint16_t requestConn = passkeyRequestConn;
#else
        const uint16_t requestConn = BLE_HS_CONN_HANDLE_NONE;
#endif

        if (config.bluetooth.mode == meshtastic_Config_BluetoothConfig_PairingMode_RANDOM_PIN) {
            // A new 6-digit PIN for every pairing procedure, never reused: each failed passkey entry reveals bits of it.
            passkey = random(100000, 999999);
            if (pairingPin.heldByOther(requestConn, ble_gap_conn_find(pairingPin.owner(), nullptr) == 0)) {
                // Neither share the PIN on screen nor replace it under the central that is pairing with it.
                LOG_WARN("BLE conn %u refused: conn %u is pairing with the PIN on screen", requestConn, pairingPin.owner());
                bleServer->disconnect(requestConn);
                return passkey; // never shown
            }
            LOG_INFO("Use random passkey");
        }
        LOG_INFO("*** Enter passkey %d on the peer side ***", passkey);

        powerFSM.trigger(EVENT_BLUETOOTH_PAIR);
        meshtastic::BluetoothStatus newStatus(std::to_string(passkey));
        bluetoothStatus->updateStatus(&newStatus);

#if HAS_SCREEN // Todo: migrate this display code back into Screen class, and observe bluetoothStatus
        if (screen) {
            screen->startAlert([passkey](OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y) -> void {
                char btPIN[16] = "888888";
                snprintf(btPIN, sizeof(btPIN), "%06u", passkey);
                int x_offset = display->width() / 2;
                int y_offset = display->height() <= 80 ? 0 : 12;
                display->setTextAlignment(TEXT_ALIGN_CENTER);
                display->setFont(FONT_MEDIUM);
                display->drawString(x_offset + x, y_offset + y, "Bluetooth");
#if !defined(OLED_TINY)
                display->setFont(FONT_SMALL);
                y_offset = display->height() == 64 ? y_offset + FONT_HEIGHT_MEDIUM - 4 : y_offset + FONT_HEIGHT_MEDIUM + 5;
                display->drawString(x_offset + x, y_offset + y, "Enter this code");
#endif
                display->setFont(FONT_LARGE);
                char pin[8];
                snprintf(pin, sizeof(pin), "%.3s %.3s", btPIN, btPIN + 3);
                y_offset = display->height() == 64 ? y_offset + FONT_HEIGHT_SMALL - 5 : y_offset + FONT_HEIGHT_SMALL + 5;
                display->drawString(x_offset + x, y_offset + y, pin);

                display->setFont(FONT_SMALL);
                char deviceName[64];
                snprintf(deviceName, sizeof(deviceName), "Name: %s", getDeviceName());
                y_offset = display->height() == 64 ? y_offset + FONT_HEIGHT_LARGE - 6 : y_offset + FONT_HEIGHT_LARGE + 5;
                display->drawString(x_offset + x, y_offset + y, deviceName);
            });
        }
#endif
        pairingPin.show(requestConn);

        return passkey;
    }

#ifdef NIMBLE_TWO
    virtual void onAuthenticationComplete(NimBLEConnInfo &connInfo)
#else
    virtual void onAuthenticationComplete(ble_gap_conn_desc *desc)
#endif
    {
        LOG_INFO("BLE authentication complete");

        meshtastic::BluetoothStatus newStatus(meshtastic::BluetoothStatus::ConnectionState::CONNECTED);
        bluetoothStatus->updateStatus(&newStatus);

        // Success or failure: that connection's pairing is over. The connection already has its slot (claimed in onConnect).
#ifdef NIMBLE_TWO
        releasePairingDisplay(connInfo.getConnHandle());
#else
        releasePairingDisplay(desc->conn_handle);
#endif
    }

    /// NimBLE task: give a new connection its client slot, or refuse it when every slot is taken.
    void onCentralConnected(NimBLEServer *pServer, uint16_t connHandle)
    {
#if MAX_BLE_PHONE_CLIENTS > 1
        trackPasskeyRequests(connHandle);
#endif
        int slot = bleSlots.claim(connHandle);
        if (slot < 0) {
            LOG_WARN("BLE conn %u refused: all %u BLE client slots in use", connHandle, (unsigned)bleSlots.usable());
            pServer->disconnect(connHandle);
            return;
        }
        LOG_INFO("BLE conn %u uses client slot %d (%u of %u in use)", connHandle, slot, (unsigned)bleSlots.count(),
                 (unsigned)bleSlots.usable());

        // The controller stops advertising when a central connects; keep advertising while another central can join.
        if (!bleSlots.full())
            resumeAdvertising();
    }

    void resumeAdvertising()
    {
#ifdef NIMBLE_TWO
        ble->startAdvertising();
#else
        NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
        if (!pAdvertising->start(0)) {
            if (pAdvertising->isAdvertising()) {
                LOG_DEBUG("BLE advertising already running");
            } else {
                LOG_ERROR("BLE failed to restart advertising");
            }
        }
#endif
    }

#ifndef NIMBLE_TWO
    virtual void onConnect(NimBLEServer *pServer, ble_gap_conn_desc *desc) override
    {
        LOG_INFO("BLE incoming connection, conn %u", desc->conn_handle);
        onCentralConnected(pServer, desc->conn_handle);
    }

    virtual void onMTUChange(uint16_t MTU, ble_gap_conn_desc *desc) override
    {
        LOG_INFO("BLE conn %u MTU %u", desc->conn_handle, MTU);
    }
#endif

#ifdef NIMBLE_TWO
    virtual void onConnect(NimBLEServer *pServer, NimBLEConnInfo &connInfo)
    {
        LOG_INFO("BLE incoming connection %s", connInfo.getAddress().toString().c_str());

        const uint16_t connHandle = connInfo.getConnHandle();
#if NIMBLE_ENABLE_2M_PHY && (defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C6))
        int phyResult =
            ble_gap_set_prefered_le_phy(connHandle, BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_CODED_ANY);
        if (phyResult == 0) {
            LOG_INFO("BLE conn %u requested 2M PHY", connHandle);
        } else {
            LOG_WARN("Failed to prefer 2M PHY for conn %u, rc=%d", connHandle, phyResult);
        }
#endif

        int dataLenResult = ble_gap_set_data_len(connHandle, kPreferredBleTxOctets, kPreferredBleTxTimeUs);
        if (dataLenResult == 0) {
            LOG_INFO("BLE conn %u requested data length %u bytes", connHandle, kPreferredBleTxOctets);
        } else {
            LOG_WARN("Failed to raise data length for conn %u, rc=%d", connHandle, dataLenResult);
        }

        LOG_INFO("BLE conn %u initial MTU %u (target %u)", connHandle, connInfo.getMTU(), kPreferredBleMtu);
        pServer->updateConnParams(connHandle, 6, 12, 0, 200);

        onCentralConnected(pServer, connHandle);
    }
#endif

#ifdef NIMBLE_TWO
    virtual void onDisconnect(NimBLEServer *pServer, NimBLEConnInfo &connInfo, int reason)
    {
        LOG_INFO("BLE disconnect reason: %d", reason);
        const uint16_t connHandle = connInfo.getConnHandle();
#else
    virtual void onDisconnect(NimBLEServer *pServer, ble_gap_conn_desc *desc)
    {
        LOG_INFO("BLE disconnect, conn %u", desc->conn_handle);
        const uint16_t connHandle = desc->conn_handle;
#endif
#ifdef NIMBLE_TWO
        if (ble->isDeInit)
            return;
#else
        if (nimbleBluetooth && nimbleBluetooth->isDeInit)
            return;
#endif

        // Hand this connection's close to its own client, then free the slot. Other centrals are untouched.
        BluetoothPhoneAPI *api = apiForConn(connHandle);
        if (api)
            api->onTransportDisconnected();
        bleSlots.release(connHandle);

        if (bleSlots.count() == 0) {
            meshtastic::BluetoothStatus newStatus(meshtastic::BluetoothStatus::ConnectionState::DISCONNECTED);
            bluetoothStatus->updateStatus(&newStatus);
        }
        releasePairingDisplay(connHandle);

        // Restart Advertising
        resumeAdvertising();
    }
};

static NimbleBluetoothToRadioCallback *toRadioCallbacks;
static NimbleBluetoothFromRadioCallback *fromRadioCallbacks;
#ifndef NIMBLE_TWO
static NimbleBluetoothFromNumCallback *fromNumCallbacks;
#endif

void NimbleBluetooth::shutdown()
{
    // No measurable power saving for ESP32 during light-sleep(?)
#ifndef ARCH_ESP32
    // Shutdown bluetooth for minimum power draw
    LOG_INFO("Disable bluetooth");
    NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->reset();
    pAdvertising->stop();
#endif
}

// Proper shutdown for ESP32. Needs reboot to reverse.
void NimbleBluetooth::deinit()
{
#ifdef ARCH_ESP32
    LOG_INFO("Disable bluetooth until reboot");
    isDeInit = true;

#ifdef BLE_LED
    digitalWrite(BLE_LED, LED_STATE_OFF);
#endif
#ifndef NIMBLE_TWO
    NimBLEDevice::deinit();
#endif
#endif
}

// Has initial setup been completed
bool NimbleBluetooth::isActive()
{
    return bleServer;
}

bool NimbleBluetooth::isConnected()
{
    return bleServer->getConnectedCount() > 0;
}

int NimbleBluetooth::getRssi()
{
#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C6)
    if (!bleServer || !isConnected()) {
        return 0; // No active BLE connection
    }

    // Main task: read the slot table only. Never write a handle back: slots belong to the NimBLE task (see bleSlots).
    uint16_t connHandle = bleSlots.firstConnectedHandle();

    if (connHandle == BLE_HS_CONN_HANDLE_NONE) {
        const auto peers = bleServer->getPeerDevices();
        if (!peers.empty()) {
            connHandle = peers.front(); // local only
        }
    }

    if (connHandle == BLE_HS_CONN_HANDLE_NONE) {
        return 0; // Connection handle not available yet
    }

    int8_t rssi = 0;
    const int rc = ble_gap_conn_rssi(connHandle, &rssi);

    if (rc == 0) {
        return rssi;
    }
    LOG_DEBUG("BLE RSSI read failed, rc=%d", rc);
#endif

    return 0;
}

void NimbleBluetooth::setup()
{
    // Uncomment for testing
    // NimbleBluetooth::clearBonds();

    LOG_INFO("Init the NimBLE bluetooth module");

    NimBLEDevice::init(getDeviceName());
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

#if NIMBLE_ENABLE_2M_PHY && (defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C6))
    int mtuResult = NimBLEDevice::setMTU(kPreferredBleMtu);
    if (mtuResult == 0) {
        LOG_INFO("BLE MTU request set to %u", kPreferredBleMtu);
    } else {
        LOG_WARN("Unable to request MTU %u, rc=%d", kPreferredBleMtu, mtuResult);
    }

    int phyResult = ble_gap_set_prefered_default_le_phy(BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_2M_MASK);
    if (phyResult == 0) {
        LOG_INFO("BLE default PHY preference set to 2M");
    } else {
        LOG_WARN("Failed to prefer 2M PHY by default, rc=%d", phyResult);
    }

    int dataLenResult = ble_gap_write_sugg_def_data_len(kPreferredBleTxOctets, kPreferredBleTxTimeUs);
    if (dataLenResult == 0) {
        LOG_INFO("BLE suggested data length set to %u bytes", kPreferredBleTxOctets);
    } else {
        LOG_WARN("Failed to raise suggested data length (%u/%u), rc=%d", kPreferredBleTxOctets, kPreferredBleTxTimeUs,
                 dataLenResult);
    }
#endif

    if (config.bluetooth.mode != meshtastic_Config_BluetoothConfig_PairingMode_NO_PIN) {
        NimBLEDevice::setSecurityAuth(BLE_SM_PAIR_AUTHREQ_BOND | BLE_SM_PAIR_AUTHREQ_MITM | BLE_SM_PAIR_AUTHREQ_SC);
        NimBLEDevice::setSecurityInitKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);
        NimBLEDevice::setSecurityRespKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);
        NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
    }
    bleServer = NimBLEDevice::createServer();
#ifdef NIMBLE_TWO
    NimbleBluetoothServerCallback *serverCallbacks = new NimbleBluetoothServerCallback(this);
#else
    NimbleBluetoothServerCallback *serverCallbacks = new NimbleBluetoothServerCallback();
#endif
    bleServer->setCallbacks(serverCallbacks, true);
    setupService();
    startAdvertising();
}

void NimbleBluetooth::setupService()
{
    NimBLEService *bleService = bleServer->createService(MESH_SERVICE_UUID);
    NimBLECharacteristic *ToRadioCharacteristic;
    NimBLECharacteristic *FromRadioCharacteristic;
    // Define the characteristics that the app is looking for
    if (config.bluetooth.mode == meshtastic_Config_BluetoothConfig_PairingMode_NO_PIN) {
        ToRadioCharacteristic = bleService->createCharacteristic(TORADIO_UUID, NIMBLE_PROPERTY::WRITE);
        // Allow notifications so phones can stream FromRadio without polling.
        FromRadioCharacteristic = bleService->createCharacteristic(FROMRADIO_UUID, NIMBLE_PROPERTY::READ);
        fromNumCharacteristic = bleService->createCharacteristic(FROMNUM_UUID, NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ);
        logRadioCharacteristic =
            bleService->createCharacteristic(LOGRADIO_UUID, NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ, 512U);
    } else {
        ToRadioCharacteristic = bleService->createCharacteristic(
            TORADIO_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_AUTHEN | NIMBLE_PROPERTY::WRITE_ENC);
        FromRadioCharacteristic = bleService->createCharacteristic(
            FROMRADIO_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_AUTHEN | NIMBLE_PROPERTY::READ_ENC);
        fromNumCharacteristic =
            bleService->createCharacteristic(FROMNUM_UUID, NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ |
                                                               NIMBLE_PROPERTY::READ_AUTHEN | NIMBLE_PROPERTY::READ_ENC);
        logRadioCharacteristic = bleService->createCharacteristic(
            LOGRADIO_UUID,
            NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_AUTHEN | NIMBLE_PROPERTY::READ_ENC, 512U);
    }
    // One client per slot, allocated up front on the main task (OSThreads must not be created from the NimBLE task).
    for (uint8_t i = 0; i < MAX_BLE_PHONE_CLIENTS; i++)
        bluetoothPhoneAPIs[i] = new BluetoothPhoneAPI(i);

    toRadioCallbacks = new NimbleBluetoothToRadioCallback();
    ToRadioCharacteristic->setCallbacks(toRadioCallbacks);

    fromRadioCallbacks = new NimbleBluetoothFromRadioCallback();
    FromRadioCharacteristic->setCallbacks(fromRadioCallbacks);

#ifndef NIMBLE_TWO
    fromNumCallbacks = new NimbleBluetoothFromNumCallback();
    fromNumCharacteristic->setCallbacks(fromNumCallbacks);
    logRadioCharacteristic->setCallbacks(new NimbleBluetoothSubscriptionCallback(&BluetoothPhoneAPI::logRadioSubscription));
#endif

    bleService->start();

    // More than one central only with per-connection FromRadio long reads (see FROMRADIO LONG READS): without them a
    // central could receive bytes spliced from another central's FromRadio.
#if MAX_BLE_PHONE_CLIENTS > 1
    if (installFromRadioLongReadGuard(bleService, FromRadioCharacteristic)) {
        bleSlots.setLimit(MAX_BLE_PHONE_CLIENTS);
        LOG_INFO("BLE: up to %u centrals at once", (unsigned)MAX_BLE_PHONE_CLIENTS);
    } else {
        bleSlots.setLimit(1);
        LOG_ERROR("BLE: FromRadio long-read guard not installed, allowing one central");
    }
#else
    bleSlots.setLimit(1);
#endif

    // Setup the battery service
    NimBLEService *batteryService = bleServer->createService(NimBLEUUID((uint16_t)0x180f)); // 0x180F is the Battery Service
    BatteryCharacteristic = batteryService->createCharacteristic( // 0x2A19 is the Battery Level characteristic)
        (uint16_t)0x2a19, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY, 1);
#ifdef NIMBLE_TWO
    NimBLE2904 *batteryLevelDescriptor = BatteryCharacteristic->create2904();
#else
    NimBLE2904 *batteryLevelDescriptor = (NimBLE2904 *)BatteryCharacteristic->createDescriptor((uint16_t)0x2904);
#endif
    batteryLevelDescriptor->setFormat(NimBLE2904::FORMAT_UINT8);
    batteryLevelDescriptor->setNamespace(1);
    batteryLevelDescriptor->setUnit(0x27ad);
#ifndef NIMBLE_TWO
    BatteryCharacteristic->setCallbacks(new NimbleBluetoothSubscriptionCallback(&BluetoothPhoneAPI::batterySubscription));
#endif

    batteryService->start();
}

void NimbleBluetooth::startAdvertising()
{
#ifdef NIMBLE_TWO
    NimBLEExtAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
    NimBLEExtAdvertisement legacyAdvertising;

    legacyAdvertising.setLegacyAdvertising(true);
    legacyAdvertising.setScannable(true);
    legacyAdvertising.setConnectable(true);
    legacyAdvertising.setFlags(BLE_HS_ADV_F_DISC_GEN);
    if (powerStatus->getHasBattery() == 1) {
        legacyAdvertising.setCompleteServices(NimBLEUUID((uint16_t)0x180f));
    }
    legacyAdvertising.setCompleteServices(NimBLEUUID(MESH_SERVICE_UUID));
    legacyAdvertising.setMinInterval(500);
    legacyAdvertising.setMaxInterval(1000);

    NimBLEExtAdvertisement legacyScanResponse;
    legacyScanResponse.setLegacyAdvertising(true);
    legacyScanResponse.setConnectable(true);
    legacyScanResponse.setName(getDeviceName());

    if (!pAdvertising->setInstanceData(0, legacyAdvertising)) {
        LOG_ERROR("BLE failed to set legacyAdvertising");
    } else if (!pAdvertising->setScanResponseData(0, legacyScanResponse)) {
        LOG_ERROR("BLE failed to set legacyScanResponse");
    } else if (!pAdvertising->start(0, 0, 0)) {
        LOG_ERROR("BLE failed to start legacyAdvertising");
    }
#else
    NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->reset();
    pAdvertising->addServiceUUID(MESH_SERVICE_UUID);
    pAdvertising->addServiceUUID(NimBLEUUID((uint16_t)0x180f)); // 0x180F is the Battery Service
    pAdvertising->start(0);
#endif
}

/// Given a level between 0-100, update the BLE attribute
void updateBatteryLevel(uint8_t level)
{
    if ((config.bluetooth.enabled == true) && bleServer && nimbleBluetooth->isConnected()) {
        BatteryCharacteristic->setValue(&level, 1);
#ifdef NIMBLE_TWO
        BatteryCharacteristic->notify(&level, 1, BLE_HS_CONN_HANDLE_NONE);
#else
        notifyEachConn(BatteryCharacteristic, &BluetoothPhoneAPI::batterySubscription, &level, 1);
#endif
    }
}

void NimbleBluetooth::clearBonds()
{
    LOG_INFO("Clearing bluetooth bonds!");
    NimBLEDevice::deleteAllBonds();
}

void NimbleBluetooth::sendLog(const uint8_t *logMessage, size_t length)
{
    if (!bleServer || !isConnected() || length > 512) {
        return;
    }
#ifdef NIMBLE_TWO
    logRadioCharacteristic->notify(logMessage, length, BLE_HS_CONN_HANDLE_NONE);
#else
    notifyEachConn(logRadioCharacteristic, &BluetoothPhoneAPI::logRadioSubscription, logMessage, length);
#endif
}

void clearNVS()
{
    NimBLEDevice::deleteAllBonds();
#ifdef ARCH_ESP32
    ESP.restart();
#endif
}
#endif
