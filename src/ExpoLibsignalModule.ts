import { NativeModule, requireNativeModule } from 'expo';

import {
  ProtocolAddress,
  PreKeyBundle,
  IdentityKeyPair,
  PreKeyRecord,
  SignedPreKeyRecord,
  KyberPreKeyRecord,
  CiphertextMessage,
} from './ExpoLibsignal.types';

declare class ExpoLibsignalModule extends NativeModule {
  generateIdentityKeyPair(): Promise<IdentityKeyPair>;
  generateRegistrationId(extendedRange?: boolean): Promise<number>;
  generatePreKeys(startId: number, count: number): Promise<PreKeyRecord[]>;
  generateSignedPreKeys(signedPreKeyId: number): Promise<SignedPreKeyRecord>;
  generateKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord>;

  hasSession(address: ProtocolAddress): Promise<boolean>;
  processPreKeyBundle(address: ProtocolAddress, bundle: PreKeyBundle): Promise<void>;

  encryptMessage(address: ProtocolAddress, plaintext: string): Promise<CiphertextMessage>;
  decryptMessage(address: ProtocolAddress, ciphertext: CiphertextMessage): Promise<string>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoLibsignalModule>('ExpoLibsignal');
