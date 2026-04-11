package expo.modules.libsignal

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.signal.libsignal.protocol.IdentityKeyPair
import android.util.Base64
class ExpoLibsignalModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoLibsignal")

      AsyncFunction("generateIdentityKeyPair", this@ExpoLibsignalModule::generateIdentityKeyPair)
//      AsyncFunction("generateRegistrationId", this@ExpoLibsignalModule::generateRegistrationId)
//      AsyncFunction("generatePreKeys", this@ExpoLibsignalModule::generatePreKeys)
//      AsyncFunction("generateSignedPreKey", this@ExpoLibsignalModule::generateSignedPreKey)
  }

    private fun generateIdentityKeyPair(): Map<String, Any>{

        // 1. Generate the key pair via libsignal-client
        val keyPair: IdentityKeyPair = IdentityKeyPair.generate()

        // 2. Serialize the keys into raw ByteArrays
        val publicKeyBytes: ByteArray = keyPair.publicKey.serialize()
        val privateKeyBytes: ByteArray = keyPair.privateKey.serialize()

        // 3. Encode to Base64 strings to send over the JS Bridge
        val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
        val privateKeyBase64 = Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP)

        // 4. Return as a Kotlin Map (Expo automatically converts this to a JS Object)
        return mapOf(
            "publicKey" to publicKeyBase64,
            "privateKey" to privateKeyBase64
        )

    }

}