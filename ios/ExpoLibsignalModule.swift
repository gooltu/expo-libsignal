import ExpoModulesCore
import LibSignalClient
import Foundation

public class ExpoLibsignalModule: Module {

  private let store: iOSSignalProtocolStore = {
    guard let s = try? iOSSignalProtocolStore() else {
      fatalError("ExpoLibsignal: failed to initialize Keychain-backed store")
    }
    return s
  }()

  public func definition() -> ModuleDefinition {
    Name("ExpoLibsignal")

    // ── Key generation — private keys stored natively, never returned to JS ─

    AsyncFunction("generateIdentityKeyPair") { () throws -> [String: String] in
      let kp = IdentityKeyPair.generate()
      try self.store.storeLocalIdentityKeyPair(publicKey: kp.publicKey.publicKey, privateKey: kp.privateKey)
      return [
        "publicKey": Data(kp.publicKey.serialize()).base64EncodedString()
      ]
    }

    AsyncFunction("generateRegistrationId") { () -> Int in
      let id = UInt32.random(in: 1 ..< UInt32.max)
      self.store.storeLocalRegistrationId(id)
      return Int(id)
    }

    AsyncFunction("generatePreKeys") { (startId: Int, count: Int) throws -> [[String: Any]] in
      var preKeys: [[String: Any]] = []
      for i in 0 ..< count {
        let id = startId + i
        let privKey = PrivateKey.generate()
        let pubKey = privKey.publicKey
        let record = try LibSignalClient.PreKeyRecord(
          id: UInt32(id),
          publicKey: pubKey,
          privateKey: privKey
        )
        try self.store.storePreKey(record, id: UInt32(id), context: NullContext())
        preKeys.append([
          "id":        id,
          "publicKey": Data(pubKey.serialize()).base64EncodedString()
        ])
      }
      return preKeys
    }

    // Accepts identityKeyPair from JS but ignores it — fetches identity key from native store
    AsyncFunction("generateSignedPreKey") { (identityKeyPair: [String: String], signedPreKeyId: Int) throws -> [String: Any] in
      let identityKP = try self.store.identityKeyPair(context: NullContext())
      let privKey = PrivateKey.generate()
      let pubKeyBytes = Array(privKey.publicKey.serialize())
      let signature = try identityKP.privateKey.generateSignature(message: pubKeyBytes)
      let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)
      let record = try LibSignalClient.SignedPreKeyRecord(
        id: UInt32(signedPreKeyId),
        timestamp: timestamp,
        privateKey: privKey,
        signature: Array(signature)
      )
      try self.store.storeSignedPreKey(record, id: UInt32(signedPreKeyId), context: NullContext())
      return [
        "id":        signedPreKeyId,
        "publicKey": Data(pubKeyBytes).base64EncodedString(),
        "signature": Data(signature).base64EncodedString(),
        "timestamp": timestamp
      ]
    }

    // ── Store functions — no-ops (keys already stored natively on generation) ─

    AsyncFunction("storeIdentityKeyPair") { (_: [String: String]) in
      // Keys already stored in generateIdentityKeyPair
    }

    AsyncFunction("storeLocalRegistrationId") { (_: Int) in
      // ID already stored in generateRegistrationId
    }

    AsyncFunction("storePreKeys") { (_: [[String: Any]]) in
      // Keys already stored in generatePreKeys
    }

    AsyncFunction("storeSignedPreKey") { (_: [String: Any]) in
      // Key already stored in generateSignedPreKey
    }

    // ── Session + Crypto ───────────────────────────────────────────────────

    AsyncFunction("processPreKeyBundle") { (address: [String: Any], bundle: [String: Any]) throws in
      guard let name     = address["name"] as? String,
            let deviceId = address["deviceId"] as? Int else {
        throw NSError(domain: "ExpoLibsignal", code: 7,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid ProtocolAddress"])
      }
      guard let identityKeyB64      = bundle["identityKey"] as? String,
            let identityKeyData     = Data(base64Encoded: identityKeyB64),
            let registrationId      = bundle["registrationId"] as? Int,
            let signedPreKeyId      = bundle["signedPreKeyId"] as? Int,
            let signedPreKeyPubB64  = bundle["signedPreKeyPublic"] as? String,
            let signedPreKeyPubData = Data(base64Encoded: signedPreKeyPubB64),
            let signedPreKeySigB64  = bundle["signedPreKeySignature"] as? String,
            let signedPreKeySigData = Data(base64Encoded: signedPreKeySigB64) else {
        throw NSError(domain: "ExpoLibsignal", code: 8,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid PreKeyBundle fields"])
      }

      let preKeyId: UInt32? = (bundle["preKeyId"] as? Int).map { UInt32($0) }
      let preKeyPub: PublicKey? = try {
        guard let b64 = bundle["preKeyPublic"] as? String,
              let data = Data(base64Encoded: b64) else { return nil }
        return try PublicKey(Array(data))
      }()

      let pkBundle = try LibSignalClient.PreKeyBundle(
        registrationId:        UInt32(registrationId),
        deviceId:              UInt32(deviceId),
        prekeyId:              preKeyId,
        prekey:                preKeyPub,
        signedPrekeyId:        UInt32(signedPreKeyId),
        signedPrekey:          try PublicKey(Array(signedPreKeyPubData)),
        signedPrekeySignature: Array(signedPreKeySigData),
        identity:              try IdentityKey(publicKey: PublicKey(Array(identityKeyData)))
      )

      let remoteAddress = try ProtocolAddress(name, deviceId: UInt32(deviceId))
      try processPreKeyBundle(pkBundle, for: remoteAddress,
                              sessionStore: self.store, identityStore: self.store)
    }

    AsyncFunction("encryptMessage") { (address: [String: Any], plaintext: String) throws -> [String: Any] in
      guard let name     = address["name"] as? String,
            let deviceId = address["deviceId"] as? Int else {
        throw NSError(domain: "ExpoLibsignal", code: 7,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid ProtocolAddress"])
      }
      let plaintextData = Data(base64Encoded: plaintext) ?? Data(plaintext.utf8)
      let remoteAddress = try ProtocolAddress(name, deviceId: UInt32(deviceId))
      let ciphertext = try signalEncrypt(
        message: Array(plaintextData),
        for: remoteAddress,
        sessionStore: self.store,
        identityStore: self.store
      )
      return [
        "type": ciphertext.messageType.rawValue,
        "body": Data(ciphertext.serialize()).base64EncodedString()
      ]
    }

    AsyncFunction("decryptMessage") { (address: [String: Any], ciphertext: [String: Any]) throws -> String in
      guard let name     = address["name"] as? String,
            let deviceId = address["deviceId"] as? Int else {
        throw NSError(domain: "ExpoLibsignal", code: 7,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid ProtocolAddress"])
      }
      guard let msgType  = ciphertext["type"] as? Int,
            let bodyB64  = ciphertext["body"] as? String,
            let bodyData = Data(base64Encoded: bodyB64) else {
        throw NSError(domain: "ExpoLibsignal", code: 10,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid CiphertextMessage"])
      }
      let remoteAddress = try ProtocolAddress(name, deviceId: UInt32(deviceId))
      let plaintextBytes: [UInt8]
      switch msgType {
      case 3:
        let msg = try PreKeySignalMessage(bytes: Array(bodyData))
        plaintextBytes = try signalDecryptPreKey(
          message: msg, from: remoteAddress,
          sessionStore: self.store, identityStore: self.store,
          preKeyStore: self.store, signedPreKeyStore: self.store
        )
      case 2:
        let msg = try SignalMessage(bytes: Array(bodyData))
        plaintextBytes = try signalDecrypt(
          message: msg, from: remoteAddress,
          sessionStore: self.store, identityStore: self.store
        )
      default:
        throw NSError(domain: "ExpoLibsignal", code: 11,
                      userInfo: [NSLocalizedDescriptionKey: "Unknown message type: \(msgType)"])
      }
      return Data(plaintextBytes).base64EncodedString()
    }
  }
}
