#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <mutex>

/**
 * ToRadio queue between a transport task (e.g. NimBLE) and the main task, which also hands a disconnect over to the
 * main task so PhoneAPI::close() runs there.
 *
 * The transport task calls push() and disconnect(); the main task calls pop() / takePendingClose(). disconnect() drops
 * what is queued and sets the pending close in the same critical section in which pop() reads it, so everything pop()
 * returns after a disconnect belongs to the new connection and comes with closeFirst set: the old session is always
 * closed before the new session's first ToRadio (e.g. its want_config) is handled.
 */
template <typename T, size_t N> class SessionHandoffQueue
{
  public:
    struct PopResult {
        bool closeFirst = false; // close the old session before handling `out`
        bool havePacket = false;
    };

    /// Transport task. Returns false if the queue is full.
    bool push(const T &item)
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (count >= N)
            return false;
        items[count] = item;
        count++;
        return true;
    }

    /// Transport task: the connection is gone.
    void disconnect()
    {
        std::lock_guard<std::mutex> guard(mutex);
        count = 0;
        pendingClose = true;
    }

    /// Main task.
    PopResult pop(T &out)
    {
        PopResult result;
        std::lock_guard<std::mutex> guard(mutex);
        result.closeFirst = pendingClose.exchange(false);
        if (count > 0) {
            out = items[0];
            for (size_t i = 1; i < count; i++)
                items[i - 1] = items[i];
            count--;
            result.havePacket = true;
        }
        return result;
    }

    /// Main task. Returns true (once) if a disconnect is pending.
    bool takePendingClose()
    {
        if (!pendingClose)
            return false;
        std::lock_guard<std::mutex> guard(mutex);
        return pendingClose.exchange(false);
    }

    bool hasPendingClose() const { return pendingClose; }
    size_t size() const { return count; }
    bool isFull() const { return count >= N; }

  private:
    std::mutex mutex;
    std::atomic<size_t> count{0};
    std::atomic<bool> pendingClose{false};
    std::array<T, N> items{};
};
