package com.example.winnie.androidkeystorestudy;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Created by winnie on 2018/1/15.
 */

public class LoginKeyStoreUtils {

    private static final char[] PAS = {1,2,3,4,5,6};
    private static final byte[] IV = {2, 5, 2, 6, 3, 6, 7, 2};
    private static final IvParameterSpec IV_SPEC = new IvParameterSpec(IV);

    private static final String ENCRYPT_TYPE = "DES/CBC/PKCS5Padding";
    private static final String ALGORITHM = "DES";
    private static final String FILE_PATH = "Android_keystore_path";
    private static final int BASE_64_FLAG = Base64.URL_SAFE;

    /**
     * 加密
     */
    public static String encryptString(Context context, String data){
        //秘钥生成器
        KeyGenerator generator;
        //对称秘钥
        SecretKey secretKey;
        try {
            generator = KeyGenerator.getInstance(ALGORITHM);
            generator.init(SecureRandom.getInstance("SHA1PRNG"));
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        secretKey = generator.generateKey();

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(ENCRYPT_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV_SPEC);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        } catch (InvalidKeyException e) {
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            return null;
        }

        //加密后的数据
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(data.getBytes());
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }

        //使用keystore存储秘钥
        FileOutputStream output;
        File file = new File(context.getFilesDir(), FILE_PATH);
        if(!file.exists()){
            try {
                file.createNewFile();
            } catch (IOException e) {
                return null;
            }
        }
        try {
            output = new FileOutputStream(file);
        } catch (FileNotFoundException e) {
            return null;
        }

        //KeyStore,存储加密之后的秘钥
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
        } catch (KeyStoreException e) {
            return null;
        } catch (CertificateException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (IOException e) {
            return null;
        }

        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        try {
            keyStore.setEntry(ALGORITHM, secretKeyEntry, null);
            keyStore.store(output, PAS);
        } catch (KeyStoreException e) {
            return null;
        } catch (CertificateException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (IOException e) {
            return null;
        }

        String resultString = Base64.encodeToString(encrypted, BASE_64_FLAG);
        setSavedData(context, resultString);
        return resultString;
    }

    /**
     * 解密
     */
    public static String decryptString(Context context, String data){
        if(TextUtils.isEmpty(data)){
            data = getSavedData(context);
        }
        FileInputStream in;
        File file = new File(context.getFilesDir(), FILE_PATH);
        if(!file.exists()){
            try {
                file.createNewFile();
            } catch (IOException e) {
                return null;
            }
        }
        try {
            in = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            return null;
        }

        //KeyStore 存储着加密秘钥
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in, PAS);
        } catch (KeyStoreException e) {
            return null;
        } catch (CertificateException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (IOException e) {
            return null;
        }

        //对称秘钥
        SecretKey secretKey;
        try {
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(ALGORITHM, null);
            secretKey = secretKeyEntry.getSecretKey();
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnrecoverableEntryException e) {
            return null;
        } catch (KeyStoreException e) {
            return null;
        }

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(ENCRYPT_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IV_SPEC);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        } catch (InvalidKeyException e) {
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            return null;
        }

        //解密后的数据
        byte[] decrypted;
        try {
            decrypted = cipher.doFinal(Base64.decode(data.getBytes(), BASE_64_FLAG));
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }

        String resultString = new String(decrypted);
        return resultString;
    }

    public static String getSavedData(Context context){
        String APP = "zbj_login_sdk";
        SharedPreferences preferences = context.getSharedPreferences(APP, Context.MODE_PRIVATE);
        return preferences.getString("encrypt_data", "");
    }

    public static void setSavedData(Context context, String enctyptData) {
        String APP = "zbj_login_sdk";
        SharedPreferences preferences = context.getSharedPreferences(APP, Context.MODE_PRIVATE);
        SharedPreferences.Editor edit = preferences.edit();
        edit.putString("encrypt_data", enctyptData);
        edit.apply();
    }
}
