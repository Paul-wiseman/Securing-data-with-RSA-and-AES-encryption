package com.example.securingdata

import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.example.securingdata.cryptography.Cryptography
import com.example.securingdata.databinding.ActivityMainBinding
import com.google.android.material.textfield.TextInputLayout
import java.math.BigInteger
import java.security.*
import java.util.Calendar
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

@RequiresApi(Build.VERSION_CODES.M)
class MainActivity : AppCompatActivity() {
    private lateinit var btnEncrypt:Button
    private lateinit var btnDecrypt:Button
    private lateinit var tvDisplay:TextView
    private lateinit var tilPassword:TextInputLayout
    private lateinit var tilMessage:TextInputLayout
    private lateinit var binding: ActivityMainBinding
    private lateinit var keyStore: KeyStore

    val transformation = "RSA/ECB/PKCS1Padding"
    val provider = "AndroidKeyStore"

    private var deviceSecurityAlert: AlertDialog? = null

    private lateinit var keyguardManager: KeyguardManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
       keyStore = createAndroidKeyStore()
        keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

       createAndroidKeyStoreAsymmetricKey("MASTER_KEY")



        val cryptography = Cryptography(this)
        cryptography.keystoreTest()
        cryptography.getRSAKeys()
        btnEncrypt = binding.btnEncrypt
        btnDecrypt = binding.btnDecrypt
        tvDisplay = binding.tvDisplay
        tilPassword = binding.tilPassword
        tilMessage = binding.tilMessage




        btnEncrypt.setOnClickListener {
            val masterKey = getAndroidKeyStoreAsymmetricKeyPair("MASTER_KEY")
            val message = tilMessage.editText?.text.toString()
//            val message = cryptography.sampleJson()
            val password = tilPassword.editText?.text.toString()

//          val encrypted = cryptography.encryptWithKeyStore(message.toByteArray())
          val encrypted = encrypt(message, masterKey?.public)
            tvDisplay.text = encrypted
        }

        btnDecrypt.setOnClickListener {
            val masterKey = getAndroidKeyStoreAsymmetricKeyPair("MASTER_KEY")
            val password = binding.tilPassword.editText?.text.toString().toCharArray()
//            val result = cryptography.decryptWithKeyStore()
            val result = decrypt(tvDisplay.text.toString(), masterKey?.private)
            tvDisplay.text = result
        }
    }

    override fun onStart() {
        super.onStart()

        if (isDeviceSecure()) {
            deviceSecurityAlert = showDeviceSecurityAlert()
        }
    }

    fun isDeviceSecure(): Boolean = if (hasMarshmallow()) keyguardManager.isDeviceSecure else keyguardManager.isKeyguardSecure

    fun hasMarshmallow() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M

    // Used to block application if no lock screen is setup.
    private fun showDeviceSecurityAlert(): AlertDialog {
        return AlertDialog.Builder(this)
            .setTitle(R.string.lock_title)
            .setMessage(R.string.lock_body)
            .setPositiveButton(R.string.lock_settings, { _, _ -> /*this.openLockScreenSettings()*/ })
            .setNegativeButton(R.string.lock_exit, { _, _ -> System.exit(0) })
            .setCancelable(BuildConfig.DEBUG)
            .show()
    }



    private fun createAndroidKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore
    }


    private fun createAndroidKeyStoreAsymmetricKey(alias: String): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")

        if (hasMarshmallow()) {
            initGeneratorWithKeyGenParameterSpec(generator, alias)
        } else {
            initGeneratorWithKeyPairGeneratorSpec(generator, alias)
        }

        // Generates Key with given spec and saves it to the KeyStore
        return generator.generateKeyPair()
    }


    private fun initGeneratorWithKeyPairGeneratorSpec(generator: KeyPairGenerator, alias: String) {
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(Calendar.YEAR, 20)

        val builder = KeyPairGeneratorSpec.Builder(this)
            .setAlias(alias)
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal("CN=${alias} CA Certificate"))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)

        generator.initialize(builder.build())
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun initGeneratorWithKeyGenParameterSpec(generator: KeyPairGenerator, alias: String) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        generator.initialize(builder.build())
    }

    private fun getAndroidKeyStoreAsymmetricKeyPair(alias: String): KeyPair? {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(alias)?.publicKey


       val stringPrivateKey = privateKey?.encoded?.let { String(it) }
       val stringPublicKey = publicKey?.encoded?.let { String(it) }

        Log.i("AsymmetricKeyPair", "privateKey -------- $stringPrivateKey ")
        Log.i("AsymmetricKeyPair", "publicKey -------- $stringPublicKey ")
        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    fun removeAndroidKeyStoreKey(alias: String) = keyStore.deleteEntry(alias)


    companion object {
        var TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding"
    }

    private val cipher: Cipher = Cipher.getInstance(transformation)

    private fun encrypt(data: String, key: Key?): String {
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(bytes, Base64.DEFAULT)
    }

    private fun decrypt(data: String, key: Key?): String {
        cipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedData = Base64.decode(data, Base64.DEFAULT)
        val decodedData = cipher.doFinal(encryptedData)
        return String(decodedData)
    }
}