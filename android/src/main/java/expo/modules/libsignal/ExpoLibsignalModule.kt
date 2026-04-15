package expo.modules.libsignal

import android.util.Base64
import com.google.crypto.tink.aead.AeadConfig
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.signal.libsignal.protocol.*

import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.*
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.kem.*
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import java.security.SecureRandom

class ExpoLibsignalModule : Module() {

    private val signalStore by lazy {
        AndroidSignalProtocolStore(appContext.reactContext ?: throw Exception("React Context not found"))
    }

    override fun definition() = ModuleDefinition {
        Name("ExpoLibsignal")

        AsyncFunction("generateIdentityKeyPair", this@ExpoLibsignalModule::generateIdentityKeyPair)
        AsyncFunction("generateRegistrationId", this@ExpoLibsignalModule::generateRegistrationId)
        AsyncFunction("generatePreKeys", this@ExpoLibsignalModule::generatePreKeys)
        AsyncFunction("generateSignedPreKeys", this@ExpoLibsignalModule::generateSignedPreKeys)
        AsyncFunction("generateKyberPreKey", this@ExpoLibsignalModule::generateKyberPreKey)
        //AsyncFunction("generateSession", this@ExpoLibsignalModule::generateSession)
        AsyncFunction("hasSession", this@ExpoLibsignalModule::hasSession)
        AsyncFunction("processPreKeyBundle", this@ExpoLibsignalModule::processPreKeyBundle)
        AsyncFunction("encryptMessage", this@ExpoLibsignalModule::encryptMessage)
        AsyncFunction("decryptMessage", this@ExpoLibsignalModule::decryptMessage)

    }

    private fun generateIdentityKeyPair(): Map<String, Any>{
        // Generate the keys
        val keyPair = IdentityKeyPair.generate()

        // Automatically store securely in Native
        signalStore.storeLocalIdentityKeyPair(keyPair)

        // Return ONLY the public key to JavaScript
        val pub = Base64.encodeToString(keyPair.publicKey.serialize(), Base64.NO_WRAP)
        return mapOf("publicKey" to pub)
    }

    private fun generateRegistrationId(extendedRange: Boolean?): Int
     {
        // Generate the ID
        val secureRandom = SecureRandom()
        val useExtended = extendedRange ?: true
        val id = if (useExtended) secureRandom.nextInt(Int.MAX_VALUE - 1) + 1 else secureRandom.nextInt(16380) + 1

        // Automatically store in Native
        signalStore.storeLocalRegistrationId(id)

        // Return to JS (It's not sensitive)
        return id
    }

    private fun generatePreKeys(startId: Int, count: Int): List<Map<String, Any>>
    {
        val preKeysPublicData = mutableListOf<Map<String, Any>>()

        for (i in 0 until count) {
            val preKeyId = startId + i
            val keyPair: ECKeyPair = ECKeyPair.generate()

            // Automatically create the record and store it natively
            val record = PreKeyRecord(preKeyId, keyPair)
            signalStore.storePreKey(preKeyId, record)

            // Add ONLY the public components to the list returning to JS
            preKeysPublicData.add(mapOf(
                "id" to preKeyId,
                "publicKey" to Base64.encodeToString(keyPair.publicKey.serialize(), Base64.NO_WRAP)
            ))
        }

        return preKeysPublicData
    }

    private fun generateSignedPreKeys(signedPreKeyId: Int): Map<String, Any>
    {

        val identityKeyPair = signalStore.getIdentityKeyPair()
        val identityPrivateKey = identityKeyPair.privateKey

        // Generate the new Signed PreKey
        val keyPair: ECKeyPair = ECKeyPair.generate()
        val publicKeyBytes = keyPair.publicKey.serialize()

        // Sign it using the Native-stored Identity Key
        val signatureBytes = identityPrivateKey.calculateSignature(publicKeyBytes)
        val timestamp = System.currentTimeMillis()

        // Save the Private/Public record directly to the Native Store
        val record = SignedPreKeyRecord(
            signedPreKeyId,
            timestamp,
            keyPair,
            signatureBytes
        )
        signalStore.storeSignedPreKey(signedPreKeyId, record)

        // Return ONLY the public components and signature to JS
        return mapOf(
            "id" to signedPreKeyId,
            "publicKey" to Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP),
            "signature" to Base64.encodeToString(signatureBytes, Base64.NO_WRAP),
            "timestamp" to timestamp
        )

    }

    private fun generateKyberPreKey(kyberPreKeyId: Int): Map<String, Any>
    {
        // 1. Fetch Identity Private Key from Native Store (Never exposed to JS!)
        val identityPrivateKey = signalStore.identityKeyPair.privateKey

        // 2. Generate the Post-Quantum Key Pair
        val kyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);

        // 3. Sign the Kyber Public Key using your classical Identity Private Key
        val signatureBytes = identityPrivateKey.calculateSignature(kyberKeyPair.publicKey.serialize())
        val timestamp = System.currentTimeMillis()

        // 4. Save privately to Native Store
        val record = KyberPreKeyRecord(
            kyberPreKeyId,
            timestamp,
            kyberKeyPair,
            signatureBytes
        )
        signalStore.storeKyberPreKey(kyberPreKeyId, record)

        // 5. Return ONLY the public components to JS
        return mapOf(
            "id" to kyberPreKeyId,
            "publicKey" to Base64.encodeToString(kyberKeyPair.publicKey.serialize(), Base64.NO_WRAP),
            "signature" to Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        )

    }



    private fun hasSession(addressObj: Map<String, Any>): Boolean
    {
        val name = addressObj["name"] as String
        val deviceId = (addressObj["deviceId"] as Double).toInt()
        return signalStore.containsSession(SignalProtocolAddress(name, deviceId))
    }

    private fun processPreKeyBundle(addressObj: Map<String, Any>, bundleObj: Map<String, Any>)
    {

        val registrationId = (bundleObj["registrationId"] as Double).toInt()
        val deviceId = (bundleObj["deviceId"] as Double).toInt()
        val address = SignalProtocolAddress(addressObj["name"] as String, (addressObj["deviceId"] as Double).toInt())

        val identityKey = IdentityKey(Base64.decode(bundleObj["identityKey"] as String, Base64.NO_WRAP), 0)

        val signedPreKeyId = (bundleObj["signedPreKeyId"] as Double).toInt()
        val signedPreKeyPublic = ECPublicKey.fromPublicKeyBytes(Base64.decode(bundleObj["signedPreKeyPublic"] as String, Base64.NO_WRAP))
        val signedPreKeySignature = Base64.decode(bundleObj["signedPreKeySignature"] as String, Base64.NO_WRAP)

        val preKeyId = if (bundleObj.containsKey("preKeyId")) (bundleObj["preKeyId"] as Double).toInt() else 0
        val preKeyPublic = if (bundleObj.containsKey("preKeyPublic")) {
            ECPublicKey.fromPublicKeyBytes(Base64.decode(bundleObj["preKeyPublic"] as String, Base64.NO_WRAP))
        } else null

        val kyberPreKeyId = if (bundleObj.containsKey("kyberPreKeyId")) (bundleObj["kyberPreKeyId"] as Double).toInt() else 0

        val kyberPreKeyPublic = KEMPublicKey(Base64.decode(bundleObj["kyberPreKeyPublic"] as String, Base64.NO_WRAP))

        val kyberPreKeySignature  = Base64.decode(bundleObj["kyberPreKeySignature"] as String, Base64.NO_WRAP)

        val preKeyBundle = PreKeyBundle(
            registrationId,
            deviceId,
            preKeyId,
            preKeyPublic,
            signedPreKeyId,
            signedPreKeyPublic,
            signedPreKeySignature,
            identityKey,
            kyberPreKeyId,
            kyberPreKeyPublic,
            kyberPreKeySignature
        )

        val builder = SessionBuilder(signalStore, address)
        builder.process(preKeyBundle)
    }

    private fun encryptMessage( addressObj: Map<String, Any>, plaintext: String ): Map<String, Any?> {

        // 1. Parse the destination address
        val name = addressObj["name"] as String
        val deviceId = (addressObj["deviceId"] as Double).toInt()
        val address = SignalProtocolAddress(name, deviceId)

        // 2. Initialize the SessionCipher using the unified master store
        val cipher = SessionCipher(signalStore, address)

        // 3. Encrypt the plaintext
        // Under the hood, libsignal automatically checks your SessionStore.
        // - If this is the FIRST message in a new session, it outputs a PreKeySignalMessage (Type 3).
        // - If the session is already established, it outputs a SignalMessage (Type 2).
        val ciphertextMessage: CiphertextMessage = cipher.encrypt(plaintext.toByteArray(Charsets.UTF_8))

        // 4. Return the type and Base64 encoded payload to JavaScript
        return mapOf(
            "type" to ciphertextMessage.type, // Will automatically be 2 or 3
            "body" to Base64.encodeToString(ciphertextMessage.serialize(), Base64.NO_WRAP)
        )

    }


    private fun decryptMessage(addressObj: Map<String, Any>, messageObj: Map<String, Any>): String {

        // 1. Parse the sender's address
        val name = addressObj["name"] as String
        val deviceId = (addressObj["deviceId"] as Double).toInt()
        val address = SignalProtocolAddress(name, deviceId)

        // 2. Parse the incoming message properties
        val type = (messageObj["type"] as Double).toInt()
        val bodyBytes = Base64.decode(messageObj["body"] as String, Base64.NO_WRAP)

        // 3. Initialize the SessionCipher using the unified master store
        val cipher = SessionCipher(signalStore, address)

        // 4. Route the decryption based on the Message Type
        val decryptedBytes: ByteArray = try {
            when (type) {
                CiphertextMessage.PREKEY_TYPE -> {
                    // Type 3: Contains the sender's BaseKey to finish building the session
                    val preKeyMessage = PreKeySignalMessage(bodyBytes)
                    cipher.decrypt(preKeyMessage)
                }
                CiphertextMessage.WHISPER_TYPE -> {
                    // Type 2: Standard message for an already established session
                    val signalMessage = SignalMessage(bodyBytes)
                    cipher.decrypt(signalMessage)
                }
                else -> {
                    throw IllegalArgumentException("Unsupported expo libsignal message type: $type")
                }
            }
        } catch (e: Exception) {
            // e.g., InvalidMessageException, DuplicateMessageException, NoSessionException
            throw Exception("Failed to decrypt message from ${address.name}: ${e.message}")
        }

        // 5. Convert the decrypted bytes back to a UTF-8 String and return to JS
        return String(decryptedBytes, Charsets.UTF_8)

    }

}