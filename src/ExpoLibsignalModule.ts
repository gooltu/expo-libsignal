import { NativeModule, requireNativeModule } from 'expo';

import {  ProtocolAddress, PreKeyBundle, IdentityKeyPair, PreKeyRecord, SignedPreKeyRecord, CiphertextMessage } from './ExpoLibsignal.types';

declare class ExpoLibsignalModule extends NativeModule{
  // PI: number;
  // hello(): string;
  // setValueAsync(value: string): Promise<void>;

  generateIdentityKeyPair(): Promise<IdentityKeyPair>;
  generateRegistrationId(): Promise<number>;
  generatePreKeys(startId: number, count: number): Promise<PreKeyRecord[]>;
  generateSignedPreKey(identityKeyPair: IdentityKeyPair, signedPreKeyId: number): Promise<SignedPreKeyRecord>;

  storeIdentityKeyPair(keys: IdentityKeyPair): Promise<void>
  storeLocalRegistrationId(id: number): Promise<void>
  storePreKeys(keys: PreKeyRecord[]): Promise<void>
  storeSignedPreKey(key: SignedPreKeyRecord): Promise<void>

  processPreKeyBundle(address: ProtocolAddress, bundle: PreKeyBundle): Promise<void>

  encryptMessage(address: ProtocolAddress, plaintext: string | Uint8Array): Promise<CiphertextMessage>;
  decryptMessage(address: ProtocolAddress, ciphertext: CiphertextMessage): Promise<string | Uint8Array>;

}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoLibsignalModule>('ExpoLibsignal');
