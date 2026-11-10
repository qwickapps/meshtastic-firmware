#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

/**
 * Maps BLE connection handles to a fixed set of per-connection slots (one BluetoothPhoneAPI per slot).
 *
 * Ownership rule: only the BLE host task claims and releases slots (GAP connect / disconnect events). Every other task,
 * including the main task, only reads: find(), handleAt(), firstConnectedHandle(), count(). A reader never writes a
 * handle back into the table, so it can never resurrect a slot the host task is releasing.
 *
 * `limit` lets the owner run with fewer slots than the table holds (e.g. when the long-read guard is not available).
 */
template <size_t N> class BleSlotTable
{
  public:
    static constexpr uint16_t kNoHandle = 0xFFFF; // == BLE_HS_CONN_HANDLE_NONE
    static constexpr size_t capacity = N;

    BleSlotTable()
    {
        for (auto &h : handles)
            h.store(kNoHandle);
    }

    /// BLE host task. Returns the slot for `handle` (existing or newly claimed), or -1 if every usable slot is taken.
    int claim(uint16_t handle)
    {
        if (handle == kNoHandle)
            return -1;
        int existing = find(handle);
        if (existing >= 0)
            return existing;
        for (size_t i = 0; i < usable(); i++) {
            if (handles[i].load() == kNoHandle) {
                handles[i].store(handle);
                return (int)i;
            }
        }
        return -1;
    }

    /// BLE host task. Frees the slot of `handle`; returns its index, or -1 if the handle had no slot.
    int release(uint16_t handle)
    {
        int i = find(handle);
        if (i >= 0)
            handles[i].store(kNoHandle);
        return i;
    }

    /// Any task.
    int find(uint16_t handle) const
    {
        if (handle == kNoHandle)
            return -1;
        for (size_t i = 0; i < N; i++) {
            if (handles[i].load() == handle)
                return (int)i;
        }
        return -1;
    }

    /// Any task.
    uint16_t handleAt(size_t i) const { return i < N ? handles[i].load() : kNoHandle; }

    /// Any task. Lowest-index connected handle, or kNoHandle.
    uint16_t firstConnectedHandle() const
    {
        for (size_t i = 0; i < N; i++) {
            uint16_t h = handles[i].load();
            if (h != kNoHandle)
                return h;
        }
        return kNoHandle;
    }

    /// Any task.
    size_t count() const
    {
        size_t n = 0;
        for (size_t i = 0; i < N; i++) {
            if (handles[i].load() != kNoHandle)
                n++;
        }
        return n;
    }

    /// Any task. True when no further connection can get a slot.
    bool full() const { return count() >= usable(); }

    /// Setup only (before any connection). Clamped to [1, N].
    void setLimit(size_t newLimit) { limit = newLimit < 1 ? 1 : (newLimit > N ? N : newLimit); }
    size_t usable() const { return limit; }

  private:
    std::array<std::atomic<uint16_t>, N> handles;
    size_t limit = N;
};
