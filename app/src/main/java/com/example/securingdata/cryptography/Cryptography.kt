package com.example.securingdata.cryptography

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Base64.encodeToString
import androidx.annotation.RequiresApi
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

@RequiresApi(Build.VERSION_CODES.M)
class Cryptography(context: Context) {

    private val sharedPreferences =
        context.getSharedPreferences("Cryptography_Pref", Context.MODE_PRIVATE)
    private val editor = sharedPreferences.edit()
    private val ENCRYPTED_DATA_KEY = "ENCRYPTED_DATA_KEY"
    private val IV = "IV"
    private val SALT = "SALT"
    private val MY_KEY_ALIASE = "My_key_alias"
    private val TAG = this.javaClass.simpleName


    fun encrypt(
        dataToEncrypt: ByteArray,
        password: CharArray
    ): ByteArray {

        val map = HashMap<String, ByteArray>()

        // generating a salt
        val random = SecureRandom()
        val salt = ByteArray(256)
        random.nextBytes(salt)

        // generating the AES Key with the users password and salt
        val pbKeySpec = PBEKeySpec(password, salt, 1324, 256)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
        val keySpec = SecretKeySpec(keyBytes, "AES")

        // Adding an initialization vector
        val ivRandom = SecureRandom()
        val iv = ByteArray(16)
        ivRandom.nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)

        // encrypting the data
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        val encrypted = cipher.doFinal(dataToEncrypt)

        editor.putString(IV, Base64.encodeToString(iv, Base64.DEFAULT)).commit()
        editor.putString(SALT, Base64.encodeToString(salt, Base64.DEFAULT)).commit()
        editor.putString(ENCRYPTED_DATA_KEY, Base64.encodeToString(encrypted, Base64.DEFAULT))
            .commit()
        return encrypted
    }


    fun decrypt(password: CharArray): ByteArray? {
        var decrypted: ByteArray? = null
        val salt = Base64.decode(sharedPreferences.getString(SALT, null), Base64.DEFAULT)
        val iv = Base64.decode(sharedPreferences.getString(IV, null), Base64.DEFAULT)
        val encrypted =
            Base64.decode(sharedPreferences.getString(ENCRYPTED_DATA_KEY, null), Base64.DEFAULT)

        // 2
        //regenerate key from password
        val pbKeySpec = PBEKeySpec(password, salt, 1324, 256)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
        val keySpec = SecretKeySpec(keyBytes, "AES")

        // 3
        //Decrypt
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        decrypted = cipher.doFinal(encrypted)


        return decrypted
    }


    fun keystoreTest() {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore") // 1
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            MY_KEY_ALIASE,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            //.setUserAuthenticationRequired(true) // 2 requires lock screen, invalidated if lock screen is disabled
            //.setUserAuthenticationValidityDurationSeconds(120) // 3 only available x seconds from password authentication. -1 requires finger print - every time
            .setRandomizedEncryptionRequired(true) // 4 different ciphertext for same plaintext on each call
            .build()
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    fun encryptWithKeyStore(dataToEncrypt: ByteArray): String {
        // 1
        //Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry(MY_KEY_ALIASE, null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey

        // 2
        //Encrypt data
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val ivBytes = cipher.iv
        val encryptedBytes = cipher.doFinal(dataToEncrypt)

        editor.putString("encryptWithKeyStore_iv", Base64.encodeToString(ivBytes, Base64.DEFAULT))
            .commit()
        editor.putString(
            "encryptWithKeyStore_encrypted_data",
            Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
        ).commit()

        return String(encryptedBytes)
    }


    fun decryptWithKeyStore(): String {
        // 1
        //Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry(MY_KEY_ALIASE, null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey


        // 3
        //Decrypt data
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(
            128,
            Base64.decode(
                sharedPreferences.getString("encryptWithKeyStore_iv", null),
                Base64.DEFAULT
            )
        )
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val decreypted = cipher.doFinal(
            Base64.decode(
                sharedPreferences.getString(
                    "encryptWithKeyStore_encrypted_data",
                    null
                ), Base64.DEFAULT
            )
        )
        return String(decreypted)
    }


    // Get RSA keys. Uses key size of 2048. to create a keypair
    fun getRSAKeys() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val privateKey = keyPair.private.encoded
        val publicKey = keyPair.public.encoded
        editor.putString("privateKey", encodeToString(privateKey, Base64.DEFAULT)).commit()
        editor.putString("publicKey", encodeToString(publicKey, Base64.DEFAULT)).commit()
    }

    // Decrypt using RSA public key
    fun decryptMessageRSA(): String {
        val privateKeyString = sharedPreferences.getString("privateKey", null)
        val encryptedText = sharedPreferences.getString("EncryptedPlainText", null)
        val privateKeyBytes = Base64.decode(privateKeyString, Base64.DEFAULT)
        val privateKey: PrivateKey =
            KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(Base64.decode(encryptedText, Base64.DEFAULT)))
    }


    // Encrypt using RSA private key
    fun encryptMessageRSA(plainText: String): String {
        val publicKeyString = sharedPreferences.getString("publicKey", null)
        val publicKeyBytes = Base64.decode(publicKeyString, Base64.DEFAULT)
        val publicKey: PublicKey =
            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyBytes))
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        editor.putString(
            "EncryptedPlainText",
            encodeToString(cipher.doFinal(plainText.toByteArray()), Base64.DEFAULT)
        ).commit()
        return encodeToString(cipher.doFinal(plainText.toByteArray()), Base64.DEFAULT)
    }


    fun sampleJson(): String {
        return ""
    }


}