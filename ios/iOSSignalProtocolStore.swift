import Foundation
import CryptoKit
import LibSignalClient
import Security

class iOSSignalProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore {

    private let defaults = UserDefaults(suiteName: "expo.libsignal.store")!
    private let masterKey: SymmetricKey

    init() throws {
        self.masterKey = try iOSSignalProtocolStore.loadOrCreateMasterKey()
    }

    // ── Master key — iOS Keychain ──────────────────────────────────────────

    private static func loadOrCreateMasterKey() throws -> SymmetricKey {
        let service = "expo.libsignal.master_key"
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String:  true
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let keyData = result as? Data {
            return SymmetricKey(data: keyData)
        }
        let newKey = SymmetricKey(size: .bits256)
        let keyData = newKey.withUnsafeBytes { Data($0) }
        let addQuery: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    service,
            kSecValueData as String:      keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        guard SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess else {
            throw NSError(domain: "ExpoLibsignal", code: 100,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to save master key in Keychain"])
        }
        return newKey
    }

    // ── Encryption helpers (AES-256-GCM) ──────────────────────────────────

    private func encryptData(_ data: Data) throws -> String {
        let sealed = try AES.GCM.seal(data, using: masterKey)
        guard let combined = sealed.combined else {
            throw NSError(domain: "ExpoLibsignal", code: 101,
                          userInfo: [NSLocalizedDescriptionKey: "AES-GCM seal failed"])
        }
        return combined.base64EncodedString()
    }

    private func decryptData(_ base64: String) throws -> Data {
        guard let combined = Data(base64Encoded: base64) else {
            throw NSError(domain: "ExpoLibsignal", code: 102,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 ciphertext"])
        }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: masterKey)
    }

    // ── Identity Key Store ─────────────────────────────────────────────────

    // Called from ExpoLibsignalModule on generation — stores both halves
    func storeLocalIdentityKeyPair(publicKey: PublicKey, privateKey: PrivateKey) throws {
        defaults.set(try encryptData(Data(publicKey.serialize())),  forKey: "identity_key_pair_public")
        defaults.set(try encryptData(Data(privateKey.serialize())), forKey: "identity_key_pair_private")
    }

    func storeLocalRegistrationId(_ id: UInt32) {
        defaults.set(Int(id), forKey: "registration_id")
    }

    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair {
        guard let pubEnc  = defaults.string(forKey: "identity_key_pair_public"),
              let privEnc = defaults.string(forKey: "identity_key_pair_private") else {
            throw NSError(domain: "ExpoLibsignal", code: 103,
                          userInfo: [NSLocalizedDescriptionKey: "Identity key pair not found in store"])
        }
        let pubKey  = try PublicKey(Array(decryptData(pubEnc)))
        let privKey = try PrivateKey(Array(decryptData(privEnc)))
        return IdentityKeyPair(publicKey: IdentityKey(publicKey: pubKey), privateKey: privKey)
    }

    func localRegistrationId(context: StoreContext) throws -> UInt32 {
        return UInt32(defaults.integer(forKey: "registration_id"))
    }

    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> Bool {
        let key = "identity_\(address.name)_\(address.deviceId)"
        let existingEnc = defaults.string(forKey: key)
        defaults.set(try encryptData(Data(identity.publicKey.serialize())), forKey: key)
        // AES-GCM nonce is random so ciphertexts always differ; return true if key was already stored
        return existingEnc != nil
    }

    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool {
        let key = "identity_\(address.name)_\(address.deviceId)"
        guard let existingEnc = defaults.string(forKey: key) else { return true }  // TOFU
        let savedBytes = try decryptData(existingEnc)
        return savedBytes == Data(identity.publicKey.serialize())
    }

    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        guard let enc = defaults.string(forKey: "identity_\(address.name)_\(address.deviceId)") else {
            return nil
        }
        return try IdentityKey(publicKey: PublicKey(Array(decryptData(enc))))
    }

    // ── Pre Key Store ──────────────────────────────────────────────────────

    func loadPreKey(id: UInt32, context: StoreContext) throws -> LibSignalClient.PreKeyRecord {
        guard let enc = defaults.string(forKey: "prekey_\(id)") else {
            throw SignalError.invalidKeyIdentifier("No pre-key \(id)")
        }
        return try LibSignalClient.PreKeyRecord(bytes: Array(decryptData(enc)))
    }

    func storePreKey(_ record: LibSignalClient.PreKeyRecord, id: UInt32, context: StoreContext) throws {
        defaults.set(try encryptData(Data(try record.serialize())), forKey: "prekey_\(id)")
    }

    func removePreKey(id: UInt32, context: StoreContext) throws {
        defaults.removeObject(forKey: "prekey_\(id)")
    }

    // ── Signed Pre Key Store ───────────────────────────────────────────────

    func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> LibSignalClient.SignedPreKeyRecord {
        guard let enc = defaults.string(forKey: "signed_prekey_\(id)") else {
            throw SignalError.invalidKeyIdentifier("No signed pre-key \(id)")
        }
        return try LibSignalClient.SignedPreKeyRecord(bytes: Array(decryptData(enc)))
    }

    func storeSignedPreKey(_ record: LibSignalClient.SignedPreKeyRecord, id: UInt32, context: StoreContext) throws {
        defaults.set(try encryptData(Data(try record.serialize())), forKey: "signed_prekey_\(id)")
    }

    // ── Session Store ──────────────────────────────────────────────────────

    func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        guard let enc = defaults.string(forKey: "session_\(address.name)_\(address.deviceId)") else {
            return nil
        }
        return try SessionRecord(bytes: Array(decryptData(enc)))
    }

    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        defaults.set(try encryptData(Data(try record.serialize())),
                     forKey: "session_\(address.name)_\(address.deviceId)")
    }

    // Helper used by hasSession
    func containsSession(for address: ProtocolAddress) throws -> Bool {
        return (try loadSession(for: address, context: NullContext())) != nil
    }
}
