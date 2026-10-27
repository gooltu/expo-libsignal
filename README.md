# expo-libsignal

An Expo native module that wraps the [Signal Protocol](https://signal.org/docs/) ([`libsignal`](https://github.com/signalapp/libsignal)) to provide end-to-end encryption primitives — identity keys, prekeys, signed prekeys, post-quantum (Kyber) prekeys, session establishment, and message encrypt/decrypt — to Expo and React Native apps.

> **Note:** the package name here is a placeholder pending a rename (the name `expo-libsignal` is already taken on npm by an unrelated package). Update this README's install command once the final name is chosen.

## Platform support

| Platform | Status |
|---|---|
| iOS | ✅ Full implementation, backed by [`LibSignalClient`](https://github.com/signalapp/libsignal/tree/main/swift) |
| Android | ✅ Full implementation, backed by `org.signal:libsignal-client` / `libsignal-android` |
| Web | ⚠️ **Not implemented.** `@signalapp/libsignal-client` is a native Node.js addon with no browser/WASM build, so it cannot run in an actual browser. Every method on web is a dummy stub that returns placeholder data and does no real cryptography or persistence. Don't build on top of it assuming it works. |

Private keys never cross the JS boundary on iOS/Android: every `generate*` function stores the private half directly in native storage (Android Keystore / iOS Keychain, both AES-256-GCM encrypted at rest) and returns only the public half to JS.

This module uses native code, so it is **not compatible with Expo Go** — it requires a [custom development build](https://docs.expo.dev/develop/development-builds/introduction/) (`expo prebuild` + `expo run:ios` / `expo run:android`, or an EAS development build).

## Installation

```sh
npx expo install expo-libsignal
```

Add the module's config plugin to your `app.json` / `app.config.js` (it injects Signal's Maven repository and Android core-library-desugaring settings on Android, and the `LibSignalClient` CocoaPods source + dynamic framework linkage on iOS — none of this works without it):

```json
{
  "expo": {
    "plugins": ["expo-libsignal"]
  }
}
```

Then generate the native projects and run a development build:

```sh
npx expo prebuild
npx expo run:ios
npx expo run:android
```

## Usage

```ts
import Libsignal from 'expo-libsignal';
import type { ProtocolAddress, PreKeyBundle } from 'expo-libsignal';

// 1. Generate and publish your own key material (to your own server, not
//    shown here) so peers can establish a session with you.
const identity = await Libsignal.generateIdentityKeyPair();
const registrationId = await Libsignal.generateRegistrationId();
const [preKey] = await Libsignal.generatePreKeys(1, 1);
const signedPreKey = await Libsignal.generateSignedPreKeys(1);
const kyberPreKey = await Libsignal.generateKyberPreKey(1);

const myBundle: PreKeyBundle = {
  identityKey: identity.publicKey,
  registrationId,
  deviceId: 1,
  preKeyId: preKey.id,
  preKeyPublic: preKey.publicKey,
  signedPreKeyId: signedPreKey.id,
  signedPreKeyPublic: signedPreKey.publicKey,
  signedPreKeySignature: signedPreKey.signature,
  kyberPreKeyId: kyberPreKey.id,
  kyberPreKeyPublic: kyberPreKey.publicKey,
  kyberPreKeySignature: kyberPreKey.signature,
};

// 2. Establish an outbound session using a bundle fetched for a peer
//    (e.g. from your server).
const peer: ProtocolAddress = { name: 'peer-user-id', deviceId: 1 };
const peerBundle: PreKeyBundle = /* fetched from your server */;
await Libsignal.processPreKeyBundle(peer, peerBundle);

// 3. Encrypt and decrypt messages over the established session.
const ciphertext = await Libsignal.encryptMessage(peer, 'hello, signal');
const plaintext = await Libsignal.decryptMessage(peer, ciphertext);
```

See [`example/App.tsx`](./example/App.tsx) for a full, runnable two-party encrypt/decrypt flow you can exercise in the example app.

## API

All methods are async and resolve/reject via native promises.

| Method | Description |
|---|---|
| `generateIdentityKeyPair()` | Generates and stores a new identity key pair. Returns the public key only. |
| `generateRegistrationId(extendedRange?: boolean)` | Generates and stores a random registration ID. `extendedRange` (default `true`) picks from `[1, Int32.max - 1]`; `false` picks from `[1, 16380]`. |
| `generatePreKeys(startId: number, count: number)` | Generates and stores `count` one-time EC prekeys starting at `startId`. Returns their public halves. |
| `generateSignedPreKeys(signedPreKeyId: number)` | Generates and stores a signed prekey (signed with the stored identity key), returning its public half + signature. |
| `generateKyberPreKey(kyberPreKeyId: number)` | Generates and stores a post-quantum Kyber prekey, returning its public half + signature. |
| `hasSession(address: ProtocolAddress)` | Returns whether a session already exists with `address`. |
| `processPreKeyBundle(address: ProtocolAddress, bundle: PreKeyBundle)` | Establishes an outbound session with `address` using their published `PreKeyBundle`. |
| `encryptMessage(address: ProtocolAddress, plaintext: string)` | Encrypts `plaintext` for `address` using the existing session. Returns a `CiphertextMessage`. |
| `decryptMessage(address: ProtocolAddress, ciphertext: CiphertextMessage)` | Decrypts a `CiphertextMessage` from `address`, completing session setup if it's the first message. Returns plaintext. |

### Types

```ts
interface ProtocolAddress {
  name: string;      // usually a phone number or UUID
  deviceId: number;  // 1 for the primary device, 2+ for linked devices
}

interface PreKeyBundle {
  identityKey: string;           // base64
  registrationId: number;
  deviceId: number;
  preKeyId?: number;
  preKeyPublic?: string;         // base64
  signedPreKeyId: number;
  signedPreKeyPublic: string;    // base64
  signedPreKeySignature: string; // base64
  kyberPreKeyId: number;
  kyberPreKeyPublic: string;     // base64
  kyberPreKeySignature: string;  // base64
}

interface CiphertextMessage {
  type: number;  // 2 = SignalMessage (established session), 3 = PreKeySignalMessage (first message of a new session)
  body: string;  // base64 ciphertext
}
```

`IdentityKeyPair`, `PreKeyRecord`, `SignedPreKeyRecord`, and `KyberPreKeyRecord` are also exported — see [`src/ExpoLibsignal.types.ts`](./src/ExpoLibsignal.types.ts) for their full shapes.

## Example app

A standalone Expo app exercising the full module API — key generation, bundle exchange, session establishment, and encrypt/decrypt between two simulated parties on one screen — lives in [`example/`](./example). To run it:

```sh
cd example
npm install
npx expo run:ios      # or
npx expo run:android
```

## Contributing

Issues and pull requests are welcome at [github.com/gooltu/expo-libsignal](https://github.com/gooltu/expo-libsignal). See [`CLAUDE.md`](./CLAUDE.md) for an overview of the module's architecture and the commands used to build/lint/test it.

## License

MIT — see [LICENSE](./LICENSE).
