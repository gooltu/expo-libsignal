import * as Signal from '@signalapp/libsignal-client';
import { EncryptedSignalStore } from './webstore/EncryptedSignalStore.web';
import { registerWebModule, NativeModule } from 'expo';

import type {
  ProtocolAddress,
  IdentityKeyPair,
  CiphertextMessage,
  PreKeyBundle,
  PreKeyRecord,
  SignedPreKeyRecord,
} from './ExpoLibsignal.types';

// ==========================================
// Module-level singletons
// ==========================================
const store = new EncryptedSignalStore();
let localAddress: Signal.ProtocolAddress;

// ==========================================
// Base64 helpers
// ==========================================
function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToBuffer(base64: string): Uint8Array<ArrayBuffer> {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return bytes as Uint8Array<ArrayBuffer>;
}

class ExpoLibsignalModule extends NativeModule {

  /**
   * Must be called before any other method.
   * @param storagePassword  Derives the AES-256-GCM key used to encrypt localStorage.
   * @param localName        This device's identifier (phone number, UUID, ACI).
   * @param localDeviceId    This device's ID (1 = primary, 2+ = linked).
   */
  async initialize(storagePassword: string, localName: string, localDeviceId: number): Promise<void> {
    await store.initializeCrypto(storagePassword);
    localAddress = Signal.ProtocolAddress.new(localName, localDeviceId);
  }

  // ==========================================
  // KEY GENERATION
  // Private keys are stored inside the module and never returned to the caller.
  // The privateKey field in each response is intentionally empty ("").
  // ==========================================

  async generateIdentityKeyPair(): Promise<IdentityKeyPair> {
    const kp = Signal.IdentityKeyPair.generate();
    await store.storeIdentityKeyPair(kp);
    return { publicKey: bufferToBase64(kp.publicKey.serialize()), privateKey: '' };
  }

  async generateRegistrationId(): Promise<number> {
    const buf = new Uint16Array(1);
    window.crypto.getRandomValues(buf);
    const id = (buf[0] % 16380) + 1;
    await store.storeLocalRegistrationId(id);
    return id;
  }

  async generatePreKeys(startId: number, count: number): Promise<PreKeyRecord[]> {
    const result: PreKeyRecord[] = [];
    for (let i = 0; i < count; i++) {
      const id = startId + i;
      const privateKey = Signal.PrivateKey.generate();
      const publicKey = privateKey.getPublicKey();
      const record = Signal.PreKeyRecord.new(id, publicKey, privateKey);
      await store.savePreKey(id, record);
      result.push({ id, publicKey: bufferToBase64(publicKey.serialize()), privateKey: '' });
    }
    return result;
  }

  async generateSignedPreKey(
    _identityKeyPair: IdentityKeyPair,
    signedPreKeyId: number,
  ): Promise<SignedPreKeyRecord> {
    // Identity private key is read from the secure store — the caller's input is intentionally ignored.
    const identityPrivKey = await store.getIdentityKey();
    const privateKey = Signal.PrivateKey.generate();
    const publicKey = privateKey.getPublicKey();
    const publicKeyBytes = publicKey.serialize();
    const signature = identityPrivKey.sign(publicKeyBytes);
    const timestamp = Date.now();
    const record = Signal.SignedPreKeyRecord.new(signedPreKeyId, timestamp, publicKey, privateKey, signature);
    await store.saveSignedPreKey(signedPreKeyId, record);
    return {
      id: signedPreKeyId,
      publicKey: bufferToBase64(publicKeyBytes),
      privateKey: '',
      signature: bufferToBase64(signature),
      timestamp,
    };
  }

  // ==========================================
  // STORE METHODS
  // Keys are already stored atomically during generation above.
  // These are kept for API compatibility with the native module declaration.
  // ==========================================

  async storeIdentityKeyPair(_keys: IdentityKeyPair): Promise<void> {}

  async storeLocalRegistrationId(id: number): Promise<void> {
    await store.storeLocalRegistrationId(id);
  }

  async storePreKeys(_keys: PreKeyRecord[]): Promise<void> {}

  async storeSignedPreKey(_key: SignedPreKeyRecord): Promise<void> {}

  // ==========================================
  // SESSION ESTABLISHMENT
  // ==========================================

  async processPreKeyBundle(address: ProtocolAddress, bundle: PreKeyBundle): Promise<void> {
    const signalAddress = Signal.ProtocolAddress.new(address.name, address.deviceId);

    // Cast to any to access Kyber fields and deviceId that exist at runtime
    // but are not yet declared in the shared PreKeyBundle type.
    const b = bundle as any;

    const identityKey = Signal.PublicKey.deserialize(base64ToBuffer(bundle.identityKey));
    const signedPreKeyPublic = Signal.PublicKey.deserialize(base64ToBuffer(bundle.signedPreKeyPublic));
    const signedPreKeySignature = base64ToBuffer(bundle.signedPreKeySignature);
    const preKeyId = bundle.preKeyId ?? null;
    const preKeyPublic = bundle.preKeyPublic
      ? Signal.PublicKey.deserialize(base64ToBuffer(bundle.preKeyPublic))
      : null;

    const deviceId: number = b.deviceId ?? address.deviceId;
    const kyberPreKeyId: number = b.kyberPreKeyId ?? 0;
    const kyberPreKeyPublic = Signal.KEMPublicKey.deserialize(base64ToBuffer(b.kyberPreKeyPublic ?? ''));
    const kyberPreKeySignature = base64ToBuffer(b.kyberPreKeySignature ?? '');

    const signalBundle = Signal.PreKeyBundle.new(
      bundle.registrationId,
      deviceId,
      preKeyId,
      preKeyPublic,
      bundle.signedPreKeyId,
      signedPreKeyPublic,
      signedPreKeySignature,
      identityKey,
      kyberPreKeyId,
      kyberPreKeyPublic,
      kyberPreKeySignature,
    );

    await Signal.processPreKeyBundle(signalBundle, signalAddress, localAddress, store, store);
  }

  // ==========================================
  // MESSAGING
  // ==========================================

  async encryptMessage(
    address: ProtocolAddress,
    plaintext: string | Uint8Array,
  ): Promise<CiphertextMessage> {
    const signalAddress = Signal.ProtocolAddress.new(address.name, address.deviceId);
    const plainBytes = (
      typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext
    ) as Uint8Array<ArrayBuffer>;

    const ciphertext = await Signal.signalEncrypt(plainBytes, signalAddress, localAddress, store, store);
    return { type: ciphertext.type(), body: bufferToBase64(ciphertext.serialize()) };
  }

  async decryptMessage(
    address: ProtocolAddress,
    ciphertext: CiphertextMessage,
  ): Promise<string | Uint8Array> {
    const signalAddress = Signal.ProtocolAddress.new(address.name, address.deviceId);
    const cipherBytes = base64ToBuffer(ciphertext.body);
    let decryptedBytes: Uint8Array<ArrayBuffer>;

    if (ciphertext.type === 3) {
      // PreKeySignalMessage — first message in a new session
      const msg = Signal.PreKeySignalMessage.deserialize(cipherBytes);
      decryptedBytes = await Signal.signalDecryptPreKey(
        msg, signalAddress, localAddress, store, store, store, store, store,
      );
    } else {
      // SignalMessage — established session
      const msg = Signal.SignalMessage.deserialize(cipherBytes);
      decryptedBytes = await Signal.signalDecrypt(msg, signalAddress, localAddress, store, store);
    }

    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(decryptedBytes);
    } catch {
      return decryptedBytes;
    }
  }
}

export default registerWebModule(ExpoLibsignalModule, 'ExpoLibsignalModule');
