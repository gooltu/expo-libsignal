# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`expo-libsignal` is an Expo native module that wraps the Signal Protocol (`LibSignalClient` on iOS, `org.signal:libsignal-client`/`libsignal-android` on Android) to provide end-to-end encryption primitives (identity keys, prekeys, signed prekeys, Kyber post-quantum prekeys, session establishment, message encrypt/decrypt) to Expo/React Native apps. It follows the standard Expo module layout: a thin TypeScript API in `src/`, a native implementation per platform (`ios/`, `android/`), a **placeholder** web implementation (`src/ExpoLibsignalModule.web.ts`), and an Expo config plugin (`plugin/src/`). `example/` is a standalone Expo app used to exercise the module manually.

**Web is not a real implementation.** `@signalapp/libsignal-client` is a native Node.js addon (loaded via `node-gyp-build`/N-API, the same mechanism Signal Desktop uses under Electron) with no WASM/browser build, so it cannot run in an actual browser. `src/ExpoLibsignalModule.web.ts` only exists so the `web` platform entry in `expo-module.config.json` still resolves and type-checks; every method is a stub that returns dummy data (empty strings, `type: 2`, etc.) and does no real cryptography or persistence. Don't build on top of it assuming it works — if real web support is ever needed, it requires a different crypto library entirely.

## Commands

Run from the repo root (uses `expo-module-scripts` under the hood):

```bash
npm run build          # Compile src/ to build/ (expo-module build)
npm run clean           # Remove build output
npm run lint             # Lint (expo-module lint)
npm run test              # Run unit tests (expo-module test / jest)
npm run build:plugin        # Compile the config plugin (plugin/ -> plugin/build) via its own tsconfig
npm run prepare               # build:plugin + build — runs automatically on npm install/publish
```

Run a single test file with the underlying jest runner directly, e.g.:
```bash
npx expo-module test path/to/file.test.ts
```

Native/example app:
```bash
cd example && npm install   # first-time setup; linked to the root module via "autolinking.nativeModulesDir": ".."
npm run open:ios     # open example/ios in Xcode (xed)
npm run open:android  # open example/android in Android Studio
cd example && npm run ios      # expo run:ios
cd example && npm run android   # expo run:android
cd example && npm run web        # expo start --web
```

There is no top-level README; the `example` app's `App.tsx` is effectively the only end-to-end usage reference/smoke test for the module's JS API.

## Architecture

### Two real backend implementations (plus a dummy web stub) behind one TS surface

The module exposes one TypeScript API (`src/ExpoLibsignalModule.ts`, backed by `src/ExpoLibsignal.types.ts`), but iOS and Android implement the actual Signal Protocol logic **independently**, each with its own storage layer (see the "Web is not a real implementation" note above for why web doesn't count as a third):

| Concern | iOS | Android |
|---|---|---|
| Native glue | `ios/ExpoLibsignalModule.swift` | `android/src/main/java/expo/modules/libsignal/ExpoLibsignalModule.kt` |
| Signal store | `ios/iOSSignalProtocolStore.swift` (Keychain-backed AES-256-GCM master key, data in `UserDefaults`) | `android/src/main/java/expo/modules/libsignal/AndroidSignalProtocolStore.kt` (Android Keystore via Google Tink AEAD, data in `SharedPreferences`) |

Private keys never cross the JS boundary: every `generate*` function stores the private half directly in the native store and returns only the public half to JS (native responses omit the `privateKey` field entirely — it's optional in the TS types for this reason).

**Android is the reference implementation for this module's function surface.** iOS, the shared TS `declare class`, and the web stub are all written to match Android's function names, argument counts, and return shapes exactly:
- `generateIdentityKeyPair()`, `generatePreKeys(startId, count)` — identical everywhere.
- `generateRegistrationId(extendedRange?: boolean)` — extended (default) picks from `[1, Int32.max - 1]`; non-extended from `[1, 16380]`.
- `generateSignedPreKeys(signedPreKeyId)` — **plural**, and takes only the id; both iOS and Android fetch the identity key from their own native store rather than accepting one from JS.
- `generateKyberPreKey(kyberPreKeyId)` and `hasSession(address)` — implemented on both iOS and Android (iOS didn't have these until the realignment; see below).
- `processPreKeyBundle(address, bundle)`, `encryptMessage(address, plaintext: string)`, `decryptMessage(address, ciphertext): Promise<string>` — all 2-arg, matching Android. **iOS note:** libsignal's Swift API (unlike the legacy Java API Android uses) mandates an explicit local `ProtocolAddress` for these three calls, for session bookkeeping Android's code path doesn't have (same-account detection, address-binding in the message MAC — see `rust/protocol/src/session.rs` / `identity_key.rs::is_same_account` in signalapp/libsignal). iOS supplies a fixed internal placeholder address (`"expo-libsignal-local"`, deviceId 1) that can never parse as a Signal ServiceId, which guarantees that bookkeeping never activates — functionally equivalent to Android's lack of the concept — without requiring callers to pass anything extra. Don't reintroduce a caller-supplied `ourAddress` param; it would break the now-matching 2-arg contract.
- `decryptMessage` returns a plain (lossily-UTF8-decoded) string on every platform now, matching Android's `String(bytes, Charsets.UTF_8)`. iOS used to return base64; that's gone.
- There is **no** `storeIdentityKeyPair` / `storeLocalRegistrationId` / `storePreKeys` / `storeSignedPreKey` on any platform — Android never had them, so they were removed from the TS type, iOS, and the web stub rather than kept as no-ops.
- There is **no** `initialize(...)` or `eraseSession()` on any platform — neither ever existed on Android, which has no concept of a local address/session setup step at all (native key/session storage is created on demand by the `generate*`/`process*` calls); the example app no longer calls either.

`PreKeyBundle` (in `ExpoLibsignal.types.ts`) declares `deviceId`, `kyberPreKeyId`, `kyberPreKeyPublic`, and `kyberPreKeySignature` as required fields — both iOS and Android throw/crash if a bundle passed to `processPreKeyBundle` is missing them, so the type now says so.

When adding or changing a function, change Android last (or not at all) and bring the others up to match it — not the other way around.

### Message/session flow

Both real backends follow the same conceptual Signal Protocol flow, just with different store wiring:
1. `generateIdentityKeyPair` / `generateRegistrationId` / `generatePreKeys` / `generateSignedPreKeys` / `generateKyberPreKey` — generate and persist local key material, return only public parts for publishing to a server.
2. `processPreKeyBundle` — consumes a remote peer's published bundle (identity key, signed prekey, one-time prekey, Kyber prekey) to establish an outbound session.
3. `encryptMessage` / `decryptMessage` — use the per-peer session (`ProtocolAddress` = `{ name, deviceId }`) to produce/consume a `CiphertextMessage` (`type` 2 = `SignalMessage` on an established session, `type` 3 = `PreKeySignalMessage` for the first message of a new session, which also completes session setup on the receiving side).

### Config plugin

`plugin/src/index.ts` is a `@expo/config-plugin` (`withSignalMavenRepo`) that injects Signal's Maven repo (`https://build-artifacts.signal.org/libraries/maven/`) into the Android root `build.gradle`, required because `org.signal:libsignal-client`/`libsignal-android` aren't published to Maven Central. It's compiled separately from the main module via `plugin/tsconfig.json` and wired up via `app.plugin.js` / `expo-module.config.json`.

### expo-module.config.json

Declares native module class names per platform (`ExpoLibsignalModule` on iOS, `expo.modules.libsignal.ExpoLibsignalModule` on Android) and that `web` is also a supported platform — this is what makes Metro resolve `ExpoLibsignalModule.web.ts` instead of the native `.ts` file on web builds.
