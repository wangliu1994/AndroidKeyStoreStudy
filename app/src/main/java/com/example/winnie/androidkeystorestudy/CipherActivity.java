package com.example.winnie.androidkeystorestudy;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CipherActivity extends AppCompatActivity {

    public static final String keyStore_key = "tqf";

    TextView t1;
    TextView t2;
    TextView t3;
    SecretKey key;
    byte[] to1;
    IvParameterSpec ivSpec;
    char[] pas = {1,2,3,4,5,6};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_cipher);
        t1 = (EditText) findViewById(R.id.content);
        t2 = (Button) findViewById(R.id.encode);
        t3 = (Button) findViewById(R.id.decode);
        t2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                encode();
            }
        });
        t3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                decode();
            }
        });
        byte[] iv = {2, 5, 2, 6, 3, 6, 7, 2};
        ivSpec = new IvParameterSpec(iv);
    }

    /**
     * 加密
     */
    private void encode() {
        try {
            /**
             * 加密数据
             */
            KeyGenerator generator = KeyGenerator.getInstance("DES");
            generator.init(SecureRandom.getInstance("SHA1PRNG"));
            key = generator.generateKey();
            Cipher clipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            clipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            to1 = clipher.doFinal(t1.getText().toString().getBytes());
            t1.setText(new String(to1));

            Log.d("dddd" , new String(key.getEncoded()));
            /**
             * 使用keystore存储秘钥
             */
            FileOutputStream out = null;
            File file = new File(getFilesDir(),"tqf");
            if(!file.exists()){
                try {
                    file.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            try {
                out = new FileOutputStream(file);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key);
            keyStore.setEntry("tttt", secretKeyEntry, null);
            keyStore.store(out,pas);
        } catch (Exception e) {
            Log.d("dddd", e.getMessage());
        }
    }

    /**
     * 解密
     */
    private void decode() {
        try {
            /**
             * 在keystore里取出秘钥
             */
            FileInputStream in = null;
            File file = new File(getFilesDir(),"tqf");
            if(!file.exists()){
                try {
                    file.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            try {
                in = new FileInputStream(file);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in,pas);

            /**
             * 解密
             */
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("tttt", null);
            Cipher clipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            clipher.init(Cipher.DECRYPT_MODE, secretKeyEntry.getSecretKey(), ivSpec);
            byte[] to = clipher.doFinal(to1);
            t1.setText(new String(to));
        } catch (Exception e) {
            Log.d("dddd", e.getMessage());
        }
    }
}
