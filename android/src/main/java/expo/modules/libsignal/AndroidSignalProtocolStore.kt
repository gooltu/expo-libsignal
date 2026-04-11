package expo.modules.libsignal

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.state.*

class AndroidSignalProtocolStore (context: Context) : IdentityKeyStore {

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
            .getPrimitive(Aead::class.java)
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

    override fun getIdentityKeyPair(): IdentityKeyPair {
        val encryptedBase64 = prefs.getString("identity_key_pair", null)
            ?: throw IllegalStateException("Identity Key Pair not found.")
        return IdentityKeyPair(decryptData(encryptedBase64))
    }

    override fun getLocalRegistrationId(): Int {
        return prefs.getInt("registration_id", 0)
    }

    override fun saveIdentity(
        address: SignalProtocolAddress?,
        identityKey: IdentityKey?
    ): IdentityKeyStore.IdentityChange {

        val keyStr = "identity_${address?.name}_${address?.deviceId}"
        val existingEncrypted = prefs.getString(keyStr, null)

        val encryptedNew = encryptData(identityKey?.serialize() ?: throw IllegalArgumentException("Identity key cannot be null"))
        prefs.edit().putString(keyStr, encryptedNew).apply()

        return if (existingEncrypted == null || existingEncrypted != encryptedNew) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey?,
        direction: IdentityKeyStore.Direction
    ): Boolean {
        val keyStr = "identity_${address.name}_${address.deviceId}"
        val existingEncrypted = prefs.getString(keyStr, null) ?: return true // TOFU

        val savedBytes = decryptData(existingEncrypted)
        val incomingBytes = identityKey?.serialize()
        return savedBytes.contentEquals(incomingBytes)
    }

    override fun getIdentity(address: SignalProtocolAddress?): IdentityKey {
        val encryptedBase64 = prefs.getString("identity_${address?.name}_${address?.deviceId}", "")
        return IdentityKey(decryptData(encryptedBase64), 0)
    }
}