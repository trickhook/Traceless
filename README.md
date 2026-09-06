<h2 align="center">Zygisk Traceless</h2>

<p align="center">A Zygisk module that hides Magisk/KernelSU/APatch root traces from apps you put on the DenyList.</p>

> [!NOTE]
> This module uses [NoHello](https://github.com/MhmRdd/NoHello) source as a base to build the module.
> It isn't a "NoHello fork" — the functions are completely different.

## What it does

For every process **on the root manager's DenyList**, Traceless:

1. Builds a private, de-propagated mount namespace for the process, then uses a
   privileged **Zygisk companion** to `setns()` into it and `umount2(MNT_DETACH)`
   every root-related mount (things under `/data/adb`, `tmpfs`/`overlay` mounts
   from `magisk`/`KSU`/`APatch`/`worker`, module overlays, and magic-mount/bind
   mounts of module files).
2. Neutralizes the framework's specialization-time `unshare(CLONE_NEWNS)` so the
   app cannot escape back into the un-hidden namespace.
3. Serves a **sanitized `/proc/<pid>/maps`** (the module's own mapping is stripped)
   backed by an in-memory `memfd`, so `read`/`pread`/`lseek`/`mmap`/stdio all see
   the filtered content and behave like a real file.

Processes that were **granted root** are left completely untouched, and no work is
done for non-denylisted processes.

Additionally, `service.sh` resets a set of verified-boot/debuggable properties
(`ro.boot.verifiedbootstate`, `ro.debuggable`, `ro.build.type`, …) to their
"stock, locked" values as a basic software-property layer.

## Universal mode

By default Traceless only touches DenyList entries. **Universal mode** switches
it to hooking every non-whitelisted app spawn instead — useful when you want
hiding coverage without having to maintain a per-app list.

Toggle it with the bundled CLI (installed as `/system/bin/traceless-cli`):

```sh
su -c 'traceless-cli enable-universal'   # turn on
su -c 'traceless-cli disable-universal'  # turn off (back to denylist-only)
su -c 'traceless-cli status'             # show current mode
```

The toggle is a marker file at `/data/adb/traceless/universal.on`; changes
apply to the *next* app spawn, no reboot required.

**Whitelist (always skipped, even when universal mode is on):**

- Processes the root manager granted root (`PROCESS_GRANTED_ROOT`).
- Framework: `system_server`, `zygote`, `zygote64`, `usap32`, `usap64`,
  `webview_zygote*`.
- Root-manager packages: `com.topjohnwu.magisk`, `me.weishu.kernelsu`,
  `com.rifsxd.ksunext`, `io.github.a13e300.ksuwebui`, `me.bmax.apatch`
  (and their `:sub` process forks).
- Any `nice_name` containing `magisk`, `ksu`, or `apatch` (case-insensitive)
  — catches OEM helper processes.
- UID < 10000 (system/root/shell/services) and UID 1053 (WebView zygote).

Universal mode does **not** improve Play Integrity STRONG / DEVICE
attestation coverage — those are hardware-backed and unaffected by signature
hiding. See the Limitations section.

## Requirements & compatibility

- **Root:** Magisk (with Zygisk), KernelSU, or APatch — installed via the manager
  app (not recovery). Only one root implementation at a time.
- **ABIs:** `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`.
- **Android:** `minSdk 26` (Android 8.0) and up.

## Install

1. Add the apps you want to hide from to your root manager's **DenyList**
   (Magisk: *Configure DenyList*; enforce it).
2. Flash the Traceless zip from your root manager app and reboot.

Uninstall from the manager app; the module removes its runtime files on uninstall.

## Build

```sh
git clone --recurse-submodules https://github.com/trickhook/Traceless
cd Traceless
./gradlew :module:zipRelease   # output: module/release/Traceless-*.zip
```

The `libcxx` submodule is required (`git submodule update --init --recursive`).
The Gradle task emits a per-file SHA-256 and a `verify.sh` chain that re-checks
integrity at install time.

## Limitations

Traceless is a **signature-based mount/maps hider**, not a kernel-level solution.
It is effective against `mountinfo`/`maps` inspection from denylisted apps, but:

- Default coverage equals the DenyList's completeness. Universal mode extends
  coverage to every non-whitelisted app spawn, but does not change what a hooked
  process sees.
- Property spoofing only defeats the software-property tier; **hardware-backed key
  attestation** (Play Integrity STRONG/DEVICE) is unaffected in either mode.
- Readers using raw syscalls can still bypass the libc-level `maps` filtering.

Please report issues with your root solution, Android version, device, and a
`logcat -s Traceless` capture.

## Credits

- [NoHello](https://github.com/MhmRdd/NoHello) (source base)

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
