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

// Represents an Identity Key Pair
export interface IdentityKeyPair {
  publicKey: string;  // Base64 encoded public key
  privateKey: string; // Base64 encoded private key
}

// Represents an encrypted message
export interface CiphertextMessage {
  type: number;       // 2 for PreKeySignalMessage, 3 for SignalMessage
  body: string;       // Base64 encoded ciphertext
}

// Required to establish a session with someone for the first time
export interface PreKeyBundle {
  identityKey: string;     // Base64
  registrationId: number;
  preKeyId?: number;
  preKeyPublic?: string;   // Base64
  signedPreKeyId: number;
  signedPreKeyPublic: string; // Base64
  signedPreKeySignature: string; // Base64
}

// Represents a single One-Time PreKey generated on the device
export interface PreKeyRecord {
  id: number;
  publicKey: string;  // Base64 encoded public key
  privateKey: string; // Base64 encoded private key
  
  // Optional: The raw protobuf serialization of the entire record.
  // Useful if you are letting JS handle storage (not recommended, but common)
  serialized?: string; 
}

// Represents the Signed PreKey generated on the device
export interface SignedPreKeyRecord {
  id: number;
  publicKey: string;  // Base64 encoded public key
  privateKey: string; // Base64 encoded private key
  signature: string;  // Base64 encoded signature (signed by Identity Private Key)
  timestamp: number;  // Epoch time of when this key was generated
  
  // Optional: The raw protobuf serialization
  serialized?: string; 
}


export interface CiphertextMessage {
  // The type of message dictates how the receiver processes it.
  // 3 = PreKeySignalMessage (Used ONLY for the very first message to establish the session)
  // 2 = SignalMessage (Standard message used for all subsequent communication)
  type: number; 
  
  // The actual encrypted payload.
  // For Type 3, this includes the sender's public keys in the header.
  // For Type 2, this is just the raw encrypted ciphertext.
  body: string; // Base64 encoded ciphertext string
}