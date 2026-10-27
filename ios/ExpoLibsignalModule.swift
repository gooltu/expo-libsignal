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
      try self.store.storeLocalIdentityKeyPair(publicKey: kp.publicKey, privateKey: kp.privateKey)
      return [
        "publicKey": Data(kp.publicKey.serialize()).base64EncodedString()
      ]
    }

    AsyncFunction("generateRegistrationId") { (extendedRange: Bool?) -> Int in
      let useExtended = extendedRange ?? true
      let id = useExtended
        ? Int.random(in: 1...(Int(Int32.max) - 1))
        : Int.random(in: 1...16380)
      self.store.storeLocalRegistrationId(UInt32(id))
      return id
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

    // Fetches the identity key from the native store — there is no
    // caller-supplied identityKeyPair parameter (matches Android).
    AsyncFunction("generateSignedPreKeys") { (signedPreKeyId: Int) throws -> [String: Any] in
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

    AsyncFunction("generateKyberPreKey") { (kyberPreKeyId: Int) throws -> [String: Any] in
      let identityKP = try self.store.identityKeyPair(context: NullContext())
      let kyberKeyPair = KEMKeyPair.generate()
      let publicKeyBytes = Array(kyberKeyPair.publicKey.serialize())
      let signature = try identityKP.privateKey.generateSignature(message: publicKeyBytes)
      let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)
      let record = try LibSignalClient.KyberPreKeyRecord(
        id: UInt32(kyberPreKeyId),
        timestamp: timestamp,
        keyPair: kyberKeyPair,
        signature: Array(signature)
      )
      try self.store.storeKyberPreKey(record, id: UInt32(kyberPreKeyId), context: NullContext())
      return [
        "id":        kyberPreKeyId,
        "publicKey": Data(publicKeyBytes).base64EncodedString(),
        "signature": Data(signature).base64EncodedString()
      ]
    }

    // ── Session + Crypto ───────────────────────────────────────────────────

    AsyncFunction("hasSession") { (address: [String: Any]) throws -> Bool in
      guard let name     = address["name"] as? String,
            let deviceId = address["deviceId"] as? Int else {
        throw NSError(domain: "ExpoLibsignal", code: 7,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid ProtocolAddress"])
      }
      let remoteAddress = try ProtocolAddress(name: name, deviceId: UInt32(deviceId))
      return try self.store.containsSession(for: remoteAddress)
    }

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

      guard let kyberPreKeyIdRaw  = bundle["kyberPreKeyId"] as? Int,
            let kyberPreKeyPubB64 = bundle["kyberPreKeyPublic"] as? String,
            let kyberPreKeyPubData = Data(base64Encoded: kyberPreKeyPubB64),
            let kyberPreKeySigB64 = bundle["kyberPreKeySignature"] as? String,
            let kyberPreKeySigData = Data(base64Encoded: kyberPreKeySigB64) else {
        throw NSError(domain: "ExpoLibsignal", code: 8,
                      userInfo: [NSLocalizedDescriptionKey: "Missing Kyber pre-key fields in PreKeyBundle"])
      }
      let kyberPreKeyPub = try KEMPublicKey(Array(kyberPreKeyPubData))
      let kyberPreKeyId  = UInt32(kyberPreKeyIdRaw)

      let identityKey    = try IdentityKey(publicKey: PublicKey(Array(identityKeyData)))
      let signedPrekey   = try PublicKey(Array(signedPreKeyPubData))

      let pkBundle: LibSignalClient.PreKeyBundle
      if let preKeyId = preKeyId, let preKeyPub = preKeyPub {
        pkBundle = try LibSignalClient.PreKeyBundle(
          registrationId:        UInt32(registrationId),
          deviceId:              UInt32(deviceId),
          prekeyId:              preKeyId,
          prekey:                preKeyPub,
          signedPrekeyId:        UInt32(signedPreKeyId),
          signedPrekey:          signedPrekey,
          signedPrekeySignature: Array(signedPreKeySigData),
          identity:              identityKey,
          kyberPrekeyId:         kyberPreKeyId,
          kyberPrekey:           kyberPreKeyPub,
          kyberPrekeySignature:  Array(kyberPreKeySigData)
        )
      } else {
        pkBundle = try LibSignalClient.PreKeyBundle(
          registrationId:        UInt32(registrationId),
          deviceId:              UInt32(deviceId),
          signedPrekeyId:        UInt32(signedPreKeyId),
          signedPrekey:          signedPrekey,
          signedPrekeySignature: Array(signedPreKeySigData),
          identity:              identityKey,
          kyberPrekeyId:         kyberPreKeyId,
          kyberPrekey:           kyberPreKeyPub,
          kyberPrekeySignature:  Array(kyberPreKeySigData)
        )
      }

      let remoteAddress = try ProtocolAddress(name: name, deviceId: UInt32(deviceId))
      try processPreKeyBundle(pkBundle, for: remoteAddress,
                              sessionStore: self.store, identityStore: self.store,
                              context: NullContext())
    }

    AsyncFunction("encryptMessage") { (address: [String: Any], plaintext: String) throws -> [String: Any] in
      guard let name     = address["name"] as? String,
            let deviceId = address["deviceId"] as? Int else {
        throw NSError(domain: "ExpoLibsignal", code: 7,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid ProtocolAddress"])
      }
      let remoteAddress = try ProtocolAddress(name: name, deviceId: UInt32(deviceId))
      let ciphertext = try signalEncrypt(
        message: Array(plaintext.utf8),
        for: remoteAddress,
        sessionStore: self.store,
        identityStore: self.store,
        context: NullContext()
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
      let remoteAddress = try ProtocolAddress(name: name, deviceId: UInt32(deviceId))
      let plaintext: Data
      switch msgType {
      case 3:
        let msg = try PreKeySignalMessage(bytes: Array(bodyData))
        plaintext = try signalDecryptPreKey(
          message: msg, from: remoteAddress,
          sessionStore: self.store, identityStore: self.store,
          preKeyStore: self.store, signedPreKeyStore: self.store,
          kyberPreKeyStore: self.store,
          context: NullContext()
        )
      case 2:
        let msg = try SignalMessage(bytes: Array(bodyData))
        plaintext = try signalDecrypt(
          message: msg, from: remoteAddress,
          sessionStore: self.store, identityStore: self.store,
          context: NullContext()
        )
      default:
        throw NSError(domain: "ExpoLibsignal", code: 11,
                      userInfo: [NSLocalizedDescriptionKey: "Unknown message type: \(msgType)"])
      }
      // Lossy UTF-8 decode, matching Android's `String(bytes, Charsets.UTF_8)`.
      return String(decoding: plaintext, as: UTF8.self)
    }
  }
}
