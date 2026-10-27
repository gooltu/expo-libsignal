// import type { StyleProp, ViewStyle } from 'react-native';

// export type OnLoadEventPayload = {
//   url: string;
// };

// export type ExpoLibsignalModuleEvents = {
//   onChange: (params: ChangeEventPayload) => void;
// };

// export type ChangeEventPayload = {
//   value: string;
// };

// export type ExpoLibsignalViewProps = {
//   url: string;
//   onLoad: (event: { nativeEvent: OnLoadEventPayload }) => void;
//   style?: StyleProp<ViewStyle>;
// };


// Core Identifier for a user + device combination
export interface ProtocolAddress {
  name: string;      // Usually a phone number or UUID
  deviceId: number;  // 1 for primary device, 2+ for linked devices
}

// Represents an Identity Key Pair. privateKey is never actually returned by
// any platform — the private half stays in native storage.
export interface IdentityKeyPair {
  publicKey: string;   // Base64 encoded public key
  privateKey?: string;
}

// Represents an encrypted message
export interface CiphertextMessage {
  type: number;       // 2 for SignalMessage, 3 for PreKeySignalMessage
  body: string;       // Base64 encoded ciphertext
}

// Required to establish a session with someone for the first time.
// deviceId and the kyberPreKey* fields are mandatory — the Android/iOS
// native implementations throw if they're missing.
export interface PreKeyBundle {
  identityKey: string;     // Base64
  registrationId: number;
  deviceId: number;
  preKeyId?: number;
  preKeyPublic?: string;   // Base64
  signedPreKeyId: number;
  signedPreKeyPublic: string; // Base64
  signedPreKeySignature: string; // Base64
  kyberPreKeyId: number;
  kyberPreKeyPublic: string; // Base64
  kyberPreKeySignature: string; // Base64
}

// Represents a single One-Time PreKey generated on the device
export interface PreKeyRecord {
  id: number;
  publicKey: string;  // Base64 encoded public key
  privateKey?: string;

  // Optional: The raw protobuf serialization of the entire record.
  serialized?: string;
}

// Represents the Signed PreKey generated on the device
export interface SignedPreKeyRecord {
  id: number;
  publicKey: string;  // Base64 encoded public key
  privateKey?: string;
  signature: string;  // Base64 encoded signature (signed by Identity Private Key)
  timestamp: number;  // Epoch time of when this key was generated

  // Optional: The raw protobuf serialization
  serialized?: string;
}

// Represents a single Kyber (post-quantum) PreKey generated on the device
export interface KyberPreKeyRecord {
  id: number;
  publicKey: string;  // Base64 encoded public key
  signature: string;  // Base64 encoded signature (signed by Identity Private Key)
}
