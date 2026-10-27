import { registerWebModule, NativeModule } from 'expo';

import type {
  ProtocolAddress,
  IdentityKeyPair,
  CiphertextMessage,
  PreKeyBundle,
  PreKeyRecord,
  SignedPreKeyRecord,
  KyberPreKeyRecord,
} from './ExpoLibsignal.types';

// ==========================================
// Placeholder web implementation.
//
// @signalapp/libsignal-client is a native Node.js addon (loaded via
// node-gyp-build/N-API) and has no WASM/browser build, so it cannot run in
// an actual web target. The functions below are stubs returning dummy data,
// matching the same function set as the Android implementation (the
// reference platform for this module); they do not perform any real
// cryptography or persistence.
// ==========================================

class ExpoLibsignalModule extends NativeModule {
  async generateIdentityKeyPair(): Promise<IdentityKeyPair> {
    return { publicKey: '' };
  }

  async generateRegistrationId(_extendedRange?: boolean): Promise<number> {
    return 0;
  }

  async generatePreKeys(startId: number, count: number): Promise<PreKeyRecord[]> {
    return Array.from({ length: count }, (_, i) => ({
      id: startId + i,
      publicKey: '',
    }));
  }

  async generateSignedPreKeys(signedPreKeyId: number): Promise<SignedPreKeyRecord> {
    return {
      id: signedPreKeyId,
      publicKey: '',
      signature: '',
      timestamp: Date.now(),
    };
  }

  async generateKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord> {
    return { id: kyberPreKeyId, publicKey: '', signature: '' };
  }

  async hasSession(_address: ProtocolAddress): Promise<boolean> {
    return false;
  }

  async processPreKeyBundle(_address: ProtocolAddress, _bundle: PreKeyBundle): Promise<void> {}

  async encryptMessage(_address: ProtocolAddress, _plaintext: string): Promise<CiphertextMessage> {
    return { type: 2, body: '' };
  }

  async decryptMessage(_address: ProtocolAddress, _ciphertext: CiphertextMessage): Promise<string> {
    return '';
  }
}

export default registerWebModule(ExpoLibsignalModule, 'ExpoLibsignalModule');
