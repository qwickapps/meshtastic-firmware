# QwickMesh Wi-Fi API authentication (phase 1)

Target: outdoor gateway node "MESH", Heltec V4 (ESP32-S3 + SX1262), PlatformIO env `heltec-v4`.
Branch: `qwicknet/wifi-auth` (base `qwicknet/integration`).

Once the node is mounted outside, Wi-Fi is its only practical control and data link. Stock Meshtastic exposes the
TCP API on port 4403 to anyone on the LAN with no authentication. Phase 1 makes that port fail closed and
authenticated, without touching the serial or BLE paths.

## What changed

| Area | Change |
|---|---|
| `src/mesh/api/TcpAuth.{h,cpp}` | Handshake state machine, per-peer backoff, secret store, serial provisioning parser, protected-path check. No sockets and no Arduino calls, so it is testable natively and replaceable. |
| `src/mesh/api/ServerAPI.{h,cpp}` | Every accepted TCP connection starts *pending*. `runHandshake()` runs first; `StreamAPI`/`PhoneAPI` are not touched until it passes. The port holds one pending slot and never lets an unauthenticated peer displace the established session. |
| `src/mesh/StreamAPI.{h,cpp}` | New `onUnframedByte()` hook (default no-op). Only `SerialConsole` overrides it. |
| `src/SerialConsole.{h,cpp}` | Overrides the hook to parse `QMAUTH SET/CLEAR/STATUS` lines. USB/UART only. |
| `src/xmodem.cpp` | Refuses any path that contains `tcp_auth` or `..`, so no API client can read, overwrite or probe the key file via XModem. |
| `variants/esp32s3/heltec_v4/platformio.ini` | `MESHTASTIC_EXCLUDE_WEBSERVER=1` (the HTTP `/api/v1/toradio` path is another unauthenticated API). New env `heltec-v4-coex`. |
| `src/platform/esp32/main-esp32.cpp` | `QWICKMESH_BLE_WIFI_COEX` build flag (see below). |
| `tools/qwickmesh_tcp_auth.py` | Python client helper, CLI (`gen-secret`, `provision`, `check`) and a `meshtastic` `StreamInterface` subclass. |

**Scope.** All of the above is compiled only when `QWICKMESH_TCP_AUTH` is defined, which only `heltec-v4` and
`heltec-v4-coex` set (plus `MESHTASTIC_EXCLUDE_WEBSERVER`, moved from `heltec_v4_base` into `env:heltec-v4`). Every other
target, including other Wi-Fi ESP32 boards and the RAK4631/RAK11310 Ethernet builds, compiles the original
`APIServerPort`/`ServerAPI`/`StreamAPI`/`xmodem` code unchanged, including the RAK4631 reconnect backoff, and stock
clients keep working there.

**Revocation and session lifecycle.** `SecretStore` has a generation counter bumped by every `QMAUTH SET` and `CLEAR`.
Each connection records the generation it started under; `APIServerPort::runOnce` closes the authenticated session and
the in-flight handshake as soon as the secret is cleared or its generation changed (re-provisioning the same key also
revokes). A new session is only activated after the previous one has been closed, so two authenticated sessions never
overlap. Weak secrets (all bytes equal, including all-zero) are rejected. Per-peer failure counts decay by one per
10 quiet minutes. Handshake secret copies are wiped on every teardown path, including the destructor.

## Protocol "QMA1"

A challenge-response over HMAC-SHA256 with the 32-byte device secret `K`. It runs on the raw TCP stream, before
any 0x94C3 framing.

```
S -> C : "QMA1" || snonce[16]                                          20 bytes, sent on accept
C -> S : cnonce[16] || HMAC-SHA256(K, "QMA1-C" || snonce || cnonce)    48 bytes
S -> C : HMAC-SHA256(K, "QMA1-S" || cnonce || snonce)                  32 bytes, only if the client proof verified
         ... normal 0x94C3-framed ToRadio/FromRadio traffic ...
```

* `snonce` comes from `HardwareRNG::fill` (ESP32 hardware RNG). `cnonce` comes from the client's CSPRNG.
* The two proofs use different labels and a different nonce order, so a proof cannot be reflected back as the
  other one. Both nonces are bound into each MAC, so a recorded response is useless against a fresh `snonce`.
* The client must verify the server proof. This gives mutual authentication, so a rogue AP or host cannot pose
  as the gateway (the Python helper enforces this).
* The server reads exactly 48 bytes. Any bytes pipelined after them stay in the socket for the framing layer.
* MAC comparison is constant time. The secret is copied into the handshake object and wiped as soon as the
  proof is checked.
* Failure (bad MAC, 3 s timeout) closes the socket with no reply, so there is no oracle and no error text.

### Fail closed and backoff

* **No secret set: the TCP API is disabled.** The listener accepts, immediately closes, and constructs no
  `ServerAPI` or `PhoneAPI` object. A single warning is logged.
* **Backoff:** per peer IPv4 address, a table of 8 entries (LRU, no heap). The first 2 failures are free. From the
  3rd failure the peer is refused for 1 s, 2 s, 4 s and so on, capped at 5 min. A successful handshake clears the
  entry. Refused peers are closed before any state is allocated.
* **Pending slot:** one handshake at a time, 3 s timeout. An unauthenticated connection never closes the
  established session. Previously a new connection always replaced the old one.

## Secret storage and provisioning

* The secret is stored in its own file, `/prefs/tcp_auth.key` (32 raw bytes on LittleFS). It is **not** a field in
  `LocalConfig`, so `GetConfig`, config backup/restore and the config protobufs cannot return it. There is no
  accessor that returns it to any API: the handshake code copies it internally and nothing else can.
* XModem is the only generic file-read path in the API. It now refuses the key path. `delete_file_request` can
  still delete the file, which fails closed.
* A factory reset removes `/prefs`, so the API goes back to disabled and the device must be re-provisioned.

Provisioning is over USB serial only, as text lines. `onUnframedByte` is overridden only by `SerialConsole`, so
TCP and BLE cannot reach the parser:

```
QMAUTH SET <64 hex chars>     store a new secret (replaces the old one)
QMAUTH CLEAR                  remove it; TCP API disabled
QMAUTH STATUS                 prints "set" or "unset", never the value
```

Flow:

```
python3 tools/qwickmesh_tcp_auth.py gen-secret --out mesh.key        # mode 600, secret never printed
python3 tools/qwickmesh_tcp_auth.py provision --port <serial> --secret-file mesh.key
python3 tools/qwickmesh_tcp_auth.py check <device-ip> --secret-file mesh.key
```

The serial line buffer is zeroed after each line. The device never echoes the secret. Anyone with the USB port
has physical access and can reflash anyway, so that is the trust boundary.

## Threat model

| Threat | Status |
|---|---|
| LAN attacker connects to 4403 and talks protobuf | Blocked. No `PhoneAPI` traffic is processed before the proof verifies. |
| LAN attacker guesses the secret online | Infeasible: 256-bit key, one guess per connection, per-peer backoff, 3 s timeout. |
| Replay of a recorded handshake | Fails. The server nonce is fresh per connection and bound into the MAC. |
| Reflection (echo the device's own proof back) | Fails. Different labels and nonce order for each direction. |
| Rogue gateway impersonating MESH | Detected. The client verifies the server proof (needs `K`). |
| Timing side channel on the MAC check | Constant-time comparison. |
| Unauthenticated peer kicks the real client off | Fixed. The pending slot never displaces the established session. |
| Config/backup/XModem readback of the secret | Not in config. XModem refuses the path. |
| Unauthenticated HTTP API on the ESP32 web server | Removed from this env (`MESHTASTIC_EXCLUDE_WEBSERVER`). |
| Resource exhaustion by half-open connections | Mitigated: one pending connection, 3 s timeout, refused peers allocate nothing. |

**Residual risks (accepted in phase 1)**

* **FOLLOW-UP, required before use beyond a trusted LAN/VPN: per-frame MAC (or the TLS-PSK transport).** Not added in
  this change.
* **No confidentiality or integrity after the handshake.** Traffic is plaintext on the LAN. An on-path attacker
  can read it, or hijack the TCP stream after authentication. Use a trusted or isolated LAN, or a VPN/WireGuard
  segment until the TLS-PSK phase.
* **Handshake DoS.** A LAN attacker can occupy the one pending slot for 3 s at a time and slow the legitimate
  client's connects (not its established session). Per-IP backoff only helps against a single address; an attacker
  with many addresses is not throttled globally.
* **Shared secret.** One key per device, no rotation without USB access. Compromise of one client's key file
  compromises the device.
* **Physical access.** USB serial can set or clear the secret. The XModem path check is a name match on the file
  name, not a general ACL on the filesystem.
* **BLE is unchanged.** BLE pairing security is whatever stock Meshtastic provides (see the coexistence section).
  With coexistence on, BLE is another way to reach the same `PhoneAPI`; its PIN must be set.
* The secret is held in RAM and flash unencrypted (no flash encryption or secure boot assumed).

## Path to TLS-PSK (replaceable by design)

The handshake is isolated in `TcpAuth`; `ServerAPI` only asks "is this connection authenticated?". To swap in
TLS-PSK:

1. Wrap the accepted socket in an mbedTLS server session (`PSK_ID = "qwickmesh"`, PSK = `K`, cipher
   `TLS-PSK-WITH-AES-128-GCM-SHA256` or ChaCha20-Poly1305) and make `ServerAPI` read and write through it.
2. Replace `runHandshake()` with "TLS handshake completed". The existing backoff and pending-slot logic stay
   as they are, and the secret file and provisioning flow are reused unchanged.
3. Keep QMA1 for one release as a fallback, then remove it.

Cost to check first: mbedTLS server buffers are roughly 20–40 KB per session (PSRAM-backed allocation helps).

## Wi-Fi + BLE coexistence

Stock Meshtastic on ESP32 starts BLE only when Wi-Fi is not available (`setBluetoothEnable` in
`src/platform/esp32/main-esp32.cpp`). `QWICKMESH_BLE_WIFI_COEX` removes that condition; the env
`heltec-v4-coex` sets it. Default `heltec-v4` is unchanged.

Measured from the two builds (`pio run -e heltec-v4` and `-e heltec-v4-coex`, both succeed):

| | heltec-v4 | heltec-v4-coex |
|---|---|---|
| Flash (app) | 2,060,149 B (31.4% of 6,553,600) | 2,060,257 B (+108 B) |
| Static RAM (.data+.bss, reported by PlatformIO) | 105,384 B | 105,384 B |

Static RAM is identical because NimBLE and Wi-Fi are both linked in either way; the flag only changes whether
they run together. **Runtime heap with both active was not measured**: that needs a flashed device, and this
task did not touch hardware.

What the SDK config says (framework `qio_qspi` sdkconfig for ESP32-S3):

* `CONFIG_ESP32_WIFI_SW_COEXIST_ENABLE=1`: Wi-Fi/BT radio time-sharing is supported by the stack.
* `CONFIG_SPIRAM_USE_MALLOC=1` with `ALWAYSINTERNAL=4096`: allocations over 4 KB go to PSRAM, so large
  Wi-Fi/lwIP/NimBLE buffers do not have to fit in internal DRAM.
* Static internal RAM use is about 105 KB of the ESP32-S3's ~320 KB usable DRAM, which leaves roughly 200 KB
  for the Wi-Fi and NimBLE runtime stacks. Typical figures for those (Wi-Fi roughly 40-60 KB, NimBLE
  roughly 40-50 KB) are estimates, not measured here.

**Verdict: feasible on heltec-v4 behind the flag, not yet proven.** The build is clean and the memory budget
looks acceptable, but sign off only after a device check: boot with Wi-Fi + BLE, then log
`ESP.getFreeHeap()` and `ESP.getMinFreeHeap()` (internal and PSRAM) after a BLE connection plus an
authenticated TCP session. Two caveats:

* The repo's `boards/heltec_v4.json` configures **QSPI PSRAM (`qio_qspi`)**, and the existing variant comment says
  "2MB PSRAM". An 8 MB PSRAM variant would normally need an OPI memory type, so check which PSRAM your hardware
  has and whether a separate board definition is needed. I did not change it.
* Radio-time sharing between Wi-Fi and BLE can add latency to both.

## Tests

* Host, Python: `python3 -m pytest tools/test_qwickmesh_tcp_auth.py`
* Firmware logic (native): `pio test -e native -f test_tcp_auth` on Linux. It does not build on macOS (portduino
  needs `argp.h`). The same file was compiled and run on the host with g++ against the Crypto library and Unity:
  15 tests, 0 failures.
* Known-answer vectors are shared by both suites, so wire compatibility is checked from both sides.
* Not covered by automated tests: `ServerAPI` and `APIServerPort` over a real socket. That needs a device on
  Wi-Fi, which this task did not touch (no flashing). A LAN smoke test with the Python client is the first
  hardware step.

## Phase 2 (MeshCore-based QwickMesh firmware)

Phase 2 is a MeshCore-based QwickMesh firmware. It is **not over-the-air compatible with Meshtastic**: different
packet format, routing and crypto. Nodes running it can only talk to other MeshCore/QwickMesh nodes, so cutover
has to be per mesh, not per node. What carries over, and what has to be redone:

* Carry over: the secret and provisioning concept, the QMA1 handshake (or its TLS-PSK replacement), the Python
  helper and the backoff and pending-slot design.
* Redo: the companion/phone protocol (MeshCore has its own, not `ToRadio`/`FromRadio`, so `meshtastic`
  `StreamInterface` and the Python helper's interface class need a new adapter), the Wi-Fi server integration,
  the serial provisioning hook and the file-path protection for the new filesystem layout.
* Decide for phase 2: TLS-PSK versus per-client keys (so a client can be revoked without re-provisioning);
  an encrypted secret store (ESP32-S3 flash encryption); and a bridge or gateway node for the period when
  both firmware families share a site.
