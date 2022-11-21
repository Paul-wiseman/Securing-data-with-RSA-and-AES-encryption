package com.example.securingdata

import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.example.securingdata.cryptography.Cryptography
import com.example.securingdata.databinding.ActivityMainBinding
import com.google.android.material.textfield.TextInputLayout

@RequiresApi(Build.VERSION_CODES.M)
class MainActivity : AppCompatActivity() {
    private lateinit var btnEncrypt:Button
    private lateinit var btnDecrypt:Button
    private lateinit var tvDisplay:TextView
    private lateinit var tilPassword:TextInputLayout
    private lateinit var tilMessage:TextInputLayout
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val cryptography = Cryptography(this)
        cryptography.keystoreTest()
        cryptography.getRSAKeys()
        btnEncrypt = binding.btnEncrypt
        btnDecrypt = binding.btnDecrypt
        tvDisplay = binding.tvDisplay
        tilPassword = binding.tilPassword
        tilMessage = binding.tilMessage


        btnEncrypt.setOnClickListener {
            val message = tilMessage.editText?.text.toString()
//            val message = cryptography.sampleJson()
            val password = tilPassword.editText?.text.toString()

          val encrypted = cryptography.encryptWithKeyStore(message.toByteArray())
            tvDisplay.text = encrypted
        }

        btnDecrypt.setOnClickListener {
            val password = binding.tilPassword.editText?.text.toString().toCharArray()
            val result = cryptography.decryptWithKeyStore()
            tvDisplay.text = result
        }
    }
}