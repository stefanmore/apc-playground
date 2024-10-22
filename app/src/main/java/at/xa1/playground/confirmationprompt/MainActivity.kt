package at.xa1.playground.confirmationprompt

import android.os.Bundle
import android.security.ConfirmationPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyGenParameterSpec.Builder
import android.security.keystore.KeyProperties
import androidx.appcompat.app.AppCompatActivity
import at.xa1.playground.confirmationprompt.databinding.ActivityMainBinding
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {

    lateinit var binding: ActivityMainBinding
    lateinit var logView: LogView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        with(binding) {
            logView = LogView(logTextView, logScrollView)

            buttonShow.setOnClickListener {
                showConfirmationPrompt()
            }

            buttonShow.setOnLongClickListener {
                showConfirmationPrompt()
                showConfirmationPrompt()
                true
            }
        }

        showWelcomeMessage()
        genKeypair()
        logView.log("Now its your turn ...\n")
    }

    private fun showWelcomeMessage() {
        logView.log(
            "💡 Hey!\n" +
                "is ConfirmationPrompt supported on your device: " +
                "${ConfirmationPrompt.isSupported(this@MainActivity)}\n" +
                "press button show ConfirmationPrompt once, " +
                "long press to call showConfirmationPrompt twice.\n"+
                "---\n"
        )
    }

    private fun showConfirmationPrompt() {
        showConfirmationPrompt(
            context = this@MainActivity,
            promptText = binding.editTextPromptText.text.toString(),
            extraDataString = binding.editTextExtraData.text.toString(),
            logView = logView
        )
    }

    override fun onPause() {
        super.onPause()
        logView.log("Activity.onPause\n")
    }

    override fun onStop() {
        super.onStop()
        logView.log("Activity.onStop\n")
    }

    fun genKeypair() {
        var keyAliasName = "TestKey"
        val builder = KeyGenParameterSpec.Builder(keyAliasName, KeyProperties.PURPOSE_SIGN)
            .setUserConfirmationRequired(true)
            //.setUserAuthenticationRequired(true)
            .setUnlockedDeviceRequired(true)
            .setCertificateSubject(X500Principal(String.format("CN=%s, OU=KUL, OU=DISTIRNET, C=BE", keyAliasName)))
            .setCertificateNotBefore(Date())
            .setKeyValidityStart(Date())
            .setDigests(KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"));

        // generate key in Android keystore
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

        keyPairGenerator.initialize(builder.build());
        val keyPair = keyPairGenerator.generateKeyPair()
        logView.log("New key \"$keyAliasName\" generated!\n" +
                    "--- \n")

        getKeys()

    }

    fun getKeys() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val aliases = keyStore.aliases()

        logView.log("Keys in AndroidKeyStore: ")
        for (alias in aliases) {
            val entry = keyStore.getEntry(alias, null)
            logView.log("- $alias \n" +
                        "---")
        }
    }
}