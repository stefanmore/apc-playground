package at.xa1.playground.confirmationprompt

import android.content.Context
import android.security.ConfirmationAlreadyPresentingException
import android.security.ConfirmationCallback
import android.security.ConfirmationNotAvailableException
import android.security.ConfirmationPrompt
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.Map
import java.util.concurrent.Executor


fun showConfirmationPrompt(
    context: Context,
    promptText: String,
    extraDataString: String,
    logView: LogView
) {

    val logPrefix = "[${++showConfirmationPromptCounter}] "
    logView.log("${logPrefix}start showConfirmationPrompt")

    // Copied from https://developer.android.com/training/articles/security-android-protected-confirmation
    // and only slightly adjusted:

    val extraData: ByteArray = extraDataString.toByteArray()
    val threadReceivingCallback = Executor { runnable -> runnable.run() }
    val cborMapper = CBORMapper()

    val callback = object : ConfirmationCallback() {
        override fun onConfirmed(dataThatWasConfirmed: ByteArray) {
            super.onConfirmed(dataThatWasConfirmed)
            logView.log(
                "${logPrefix}onConfirmed: dataThatWasConfirmed =\n" +
                    "      hex: ${dataThatWasConfirmed.toHex()}\n" +
                    "      escaped ascii: ${dataThatWasConfirmed.toAsciiOrHex()}  \n" +
                    "   \n"
            )

            val decodedData = cborMapper.readValue(dataThatWasConfirmed, Map::class.java)

            logView.log("${logPrefix}onConfirmed: CBOR decoded data ")
            for (entry in decodedData.entrySet()) {
                val value =
                    when (entry.value) {
                        is String -> { entry.value as String }
                        is ByteArray -> { (entry.value as ByteArray).toAsciiOrHex() }
                        else -> { entry.value.toString() }
                    }
                logView.log("- ${entry.key}: ${value}")
            }


            // sign data that was confirmed (only possible once):
            signData(dataThatWasConfirmed)

            // now try to sign something that was not confirmed:
            //dataThatWasConfirmed.set(10, 'D'.toByte())
            //signData(dataThatWasConfirmed)

            //dataThatWasConfirmed.set(10, 'M'.toByte())
            //signData(dataThatWasConfirmed)
        }

        private fun signData(dataThatWasConfirmed: ByteArray) {
            logView.log("${logPrefix}signing with KeyStore ...")
            logView.log("escaped ascii: ${dataThatWasConfirmed.toAsciiOrHex()} ")

            try {
                val signature = initSignature("TestKey");
                checkNotNull(signature)
                signature.update(dataThatWasConfirmed)
                val signatureBytes = signature.sign()
                checkNotNull(signatureBytes)
            }catch (e: Exception) {
                logView.error("${logPrefix}signing with KeyStore throws", e)
            }

            logView.log("${logPrefix}signing done!")
        }

        private fun initSignature(keyName: String): Signature? {
            var keyPair = getKeyPair(keyName)
            if (keyPair != null) {
                val signature: Signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(keyPair.getPrivate())
                return signature
            }
            return null
        }

        private fun getKeyPair(keyName: String): KeyPair? {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            if (keyStore.containsAlias(keyName)) {
                // Get public key
                val publicKey = keyStore.getCertificate(keyName).publicKey
                // Get private key
                val privateKey = keyStore.getKey(keyName, null) as PrivateKey
                // Return a key pair
                return KeyPair(publicKey, privateKey)
            }
            return null
        }

        override fun onDismissed() {
            super.onDismissed()
            logView.log("${logPrefix}onDismissed")
        }

        override fun onCanceled() {
            super.onCanceled()
            logView.log("${logPrefix}onCanceled")
        }

        override fun onError(e: Throwable?) {
            super.onError(e)
            logView.log("${logPrefix}onError: e = $e")
        }
    }

    val dialog = try {
        ConfirmationPrompt.Builder(context)
            .setPromptText(promptText)
            .setExtraData(extraData)
            .build()
    } catch (e: IllegalArgumentException) {
        // is thrown when promptText is empty or null
        logView.error("${logPrefix}ConfirmationPrompt.Builder.build throws", e)
        return
    }

    try {
        dialog.presentPrompt(threadReceivingCallback, callback)
    } catch (e: ConfirmationAlreadyPresentingException) {
        // another confirmation is currently visible
        logView.error("${logPrefix}presentPrompt throws", e)
    } catch (e: ConfirmationNotAvailableException) {
        // device doesn't support ConfirmationPrompt
        logView.error("${logPrefix}presentPrompt throws", e)
    } catch (e: IllegalArgumentException) {
        // invalid input, e.g. a '\n' in promptText
        logView.error("${logPrefix}presentPrompt throws", e)
    }
}

var showConfirmationPromptCounter = 0