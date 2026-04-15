package expo.modules.libsignal

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.state.*
import androidx.core.content.edit
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import java.util.UUID

class AndroidSignalProtocolStore (context: Context) : SignalProtocolStore {

    init {
        // Register Tink's standard AEAD key types (AES256-GCM, etc.)
        AeadConfig.register()
    }

    // 1. Standard SharedPreferences (Values will be encrypted BEFORE saving)
    private val prefs: SharedPreferences = context.getSharedPreferences("TinkSignalStore", Context.MODE_PRIVATE)

    // 2. Initialize Google Tink AEAD (Authenticated Encryption with Associated Data)
    private val aead: Aead by lazy {
        AndroidKeysetManager.Builder()
            .withSharedPref(context, "tink_keyset", "tink_prefs")
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri("android-keystore://tink_master_key")
            .build()
            .keysetHandle
            // Pass RegistryConfiguration.get() as the first argument
            .getPrimitive(RegistryConfiguration.get(), Aead::class.java)
    }

    // --- ENCRYPTION HELPERS ---

    private fun encryptData(data: ByteArray): String {
        // Encrypt the bytes and encode the ciphertext to Base64
        val ciphertext = aead.encrypt(data, null)
        return Base64.encodeToString(ciphertext, Base64.NO_WRAP)
    }

    private fun decryptData(base64Ciphertext: String?): ByteArray {
        // Decode Base64 and decrypt back to raw bytes
        val ciphertext = Base64.decode(base64Ciphertext, Base64.NO_WRAP)
        return aead.decrypt(ciphertext, null)
    }

    // ==========================================
    // 1. IDENTITY KEY STORE
    // ==========================================

    fun storeLocalIdentityKeyPair(keyPair: IdentityKeyPair) {
        val encrypted = encryptData(keyPair.serialize())
        prefs.edit { putString("identity_key_pair", encrypted) }
    }

    fun storeLocalRegistrationId(registrationId: Int) {
        prefs.edit { putInt("registration_id", registrationId) }
    }

    override fun getIdentityKeyPair(): IdentityKeyPair {
        val encryptedBase64 = prefs.getString("identity_key_pair", null)
            ?: throw IllegalStateException("Identity Key Pair not found.")
        return IdentityKeyPair(decryptData(encryptedBase64))
    }

    override fun getLocalRegistrationId(): Int {
        return prefs.getInt("registration_id", 0)
    }

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey
    ): IdentityKeyStore.IdentityChange {

        val keyStr = "identity_${address.name}_${address.deviceId}"
        val existingEncrypted = prefs.getString(keyStr, null)

        val encryptedNew = encryptData(identityKey.serialize() ?: throw IllegalArgumentException("Identity key cannot be null"))
        prefs.edit { putString(keyStr, encryptedNew) }

        return if (existingEncrypted == null || existingEncrypted != encryptedNew) {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        } else {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        }
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction
    ): Boolean {
        val keyStr = "identity_${address.name}_${address.deviceId}"
        val existingEncrypted = prefs.getString(keyStr, null) ?: return true // TOFU

        val savedBytes = decryptData(existingEncrypted)
        val incomingBytes = identityKey.serialize()
        return savedBytes.contentEquals(incomingBytes)
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? {
        val encryptedBase64 = prefs.getString("identity_${address.name}_${address.deviceId}", null)?: return null
        return IdentityKey(decryptData(encryptedBase64), 0)
    }

    // ==========================================
    // 2. PRE KEY STORE
    // ==========================================

    override fun loadPreKey(preKeyId: Int): PreKeyRecord{
        val encryptedBase64 = prefs.getString("prekey_$preKeyId", null)?: throw InvalidKeyIdException(
            "No such PreKey: $preKeyId"
        )
        return PreKeyRecord(decryptData(encryptedBase64))
    }

    override fun storePreKey(
        preKeyId: Int,
        record: PreKeyRecord
    ) {
        prefs.edit { putString("prekey_$preKeyId", encryptData(record.serialize())) }
    }

    override fun containsPreKey(preKeyId: Int): Boolean = prefs.contains("prekey_$preKeyId")

    override fun removePreKey(preKeyId: Int) {
        prefs.edit { remove("prekey_$preKeyId") }
    }

    // ==========================================
    // 3. SIGNED PRE KEY STORE
    // ==========================================

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
        val encryptedBase64 = prefs.getString("signed_prekey_$signedPreKeyId", null)
            ?: throw InvalidKeyIdException("No such SignedPreKey: $signedPreKeyId")
        return SignedPreKeyRecord(decryptData(encryptedBase64))
    }

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord?> {
        return prefs.all.filterKeys { it.startsWith("signed_prekey_") }
            .map { SignedPreKeyRecord(decryptData(it.value as String)) }
    }

    override fun storeSignedPreKey(
        signedPreKeyId: Int,
        record: SignedPreKeyRecord
    ) {
        prefs.edit { putString("signed_prekey_$signedPreKeyId", encryptData(record.serialize())) }
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = prefs.contains("signed_prekey_$signedPreKeyId")

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        prefs.edit { remove("signed_prekey_$signedPreKeyId") }
    }

    // ==========================================
    // 4. SESSION STORE
    // ==========================================


    override fun loadSession(address: SignalProtocolAddress): SessionRecord{
        val encryptedBase64 = prefs.getString("session_${address.name}_${address.deviceId}", null)
        return if (encryptedBase64 != null) {
            SessionRecord(decryptData(encryptedBase64))
        } else {
            SessionRecord()
        }
    }

    override fun loadExistingSessions(addresses: List<SignalProtocolAddress?>?): List<SessionRecord?> {
        val results = mutableListOf<SessionRecord?>()

        // If the input list is null, return an empty list
        if (addresses == null) return results

        for (address in addresses) {
            if (address == null) {
                results.add(null)
            } else {
                // We can safely reuse our loadSession() logic here,
                // which automatically fetches, decrypts, and handles fallbacks.
                results.add(loadSession(address))
            }
        }

        return results
    }

    override fun getSubDeviceSessions(name: String): List<Int?> {
        return prefs.all.keys
            .filter { it.startsWith("session_${name}_") }
            .map { it.substringAfterLast("_").toInt() }
    }

    override fun storeSession(
        address: SignalProtocolAddress,
        record: SessionRecord
    ) {
        prefs.edit {
            putString(
                "session_${address.name}_${address.deviceId}",
                encryptData(record.serialize())
            )
        }
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean = prefs.contains("session_${address.name}_${address.deviceId}")

    override fun deleteSession(address: SignalProtocolAddress) {
        prefs.edit { remove("session_${address.name}_${address.deviceId}") }
    }

    override fun deleteAllSessions(name: String) {
        prefs.edit {
            prefs.all.keys.filter { it.startsWith("session_${name}_") }.forEach { remove(it) }
        }
    }



    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
        val encryptedBase64 = prefs.getString("kyber_prekey_$kyberPreKeyId", null)
            ?: throw InvalidKeyIdException("No such Kyber PreKey: $kyberPreKeyId")
        return KyberPreKeyRecord(decryptData(encryptedBase64))
    }

    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> {
        return prefs.all.filterKeys { it.startsWith("kyber_prekey_") }
            .map { KyberPreKeyRecord(decryptData(it.value as String)) }
    }

    override fun storeKyberPreKey(
        kyberPreKeyId: Int,
        record: KyberPreKeyRecord
    ) {
        prefs.edit { putString("kyber_prekey_$kyberPreKeyId", encryptData(record.serialize())) }
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = prefs.contains("kyber_prekey_$kyberPreKeyId")

    override fun markKyberPreKeyUsed(
        kyberPreKeyId: Int,
        signedPreKeyId: Int,
        baseKey: ECPublicKey
    ) {
        TODO("Not yet implemented")
    }

    override fun storeSenderKey(
        sender: SignalProtocolAddress?,
        distributionId: UUID?,
        record: SenderKeyRecord?
    ) {
        TODO("Not yet implemented")
    }

    override fun loadSenderKey(
        sender: SignalProtocolAddress?,
        distributionId: UUID?
    ): SenderKeyRecord? {
        return null
    }


}