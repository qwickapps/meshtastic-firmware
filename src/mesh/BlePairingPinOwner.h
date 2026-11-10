#pragma once

#include <cstdint>

/**
 * Which connection the BLE pairing PIN on screen belongs to (BLE host task only). Another connection is refused while it
 * shows, and only its own connection's authentication or disconnect takes it off screen. Owner kNoHandle = unknown.
 */
class BlePairingPinOwner
{
  public:
    static constexpr uint16_t kNoHandle = 0xFFFF; // == BLE_HS_CONN_HANDLE_NONE

    bool showing() const { return isShowing; }
    uint16_t owner() const { return ownerConn; }

    /// True if `conn` must be refused a PIN: another, still connected, connection's PIN is on screen.
    bool heldByOther(uint16_t conn, bool ownerConnected) const
    {
        return isShowing && ownerConn != kNoHandle && conn != kNoHandle && conn != ownerConn && ownerConnected;
    }

    /// A PIN for `conn` is now on screen.
    void show(uint16_t conn)
    {
        isShowing = true;
        ownerConn = conn;
    }

    /// `conn` finished authentication or disconnected. Returns true if the PIN must come off screen now.
    bool release(uint16_t conn)
    {
        if (!isShowing || (ownerConn != kNoHandle && ownerConn != conn))
            return false;
        isShowing = false;
        ownerConn = kNoHandle;
        return true;
    }

  private:
    bool isShowing = false;
    uint16_t ownerConn = kNoHandle;
};
