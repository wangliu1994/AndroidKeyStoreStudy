package com.example.winnie.androidkeystorestudy;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
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
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
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

public class LoginKeyStoreUtils1 {

    private static final String KEY_NAME = "my_android_key_name";

//    private static KeyStore keyStore;

    private static final byte[] iv = {2, 5, 2, 6, 3, 6, 7, 2};
    private static final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    private static final char[] pas = {1,2,3,4,5,6};

    /**
     * 加密
     */
    public static String encryptString(Context context, String data){
        //KeyStore
        KeyStore keyStore;
        //秘钥生成器
        KeyGenerator generator;
        //对称秘钥
        SecretKey secretKey;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
            } catch (KeyStoreException e) {
                return null;
            } catch (IOException e) {
                return null;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (CertificateException e) {
                return null;
            }

            try {
                generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_NAME,
                        KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT);
                builder.setUserAuthenticationRequired(false);
                builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC);
                builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    builder.setInvalidatedByBiometricEnrollment(true);
                }
                generator.init(builder.build());
                generator.generateKey();
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (InvalidAlgorithmParameterException e) {
                return null;
            } catch (NoSuchProviderException e) {
                return null;
            }

            try {
                secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
            } catch (KeyStoreException e) {
                return null;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (UnrecoverableKeyException e) {
                return null;
            }

            Cipher cipher;
            try {
                cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7);
                //TODO ivSpec使用进来有问题，明天来修复，全部使用API 23以下的方法
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
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

            String resultString = Base64.encodeToString(encrypted, Base64.URL_SAFE);
            return resultString;

        }else {
            try {
                generator = KeyGenerator.getInstance("DES");
                generator.init(SecureRandom.getInstance("SHA1PRNG"));
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
            secretKey = generator.generateKey();

            Cipher cipher;
            try {
                cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
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
            File file = new File(context.getFilesDir(), "keystore");
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
                keyStore.setEntry("tttt", secretKeyEntry, null);
                keyStore.store(output, pas);
            } catch (KeyStoreException e) {
                return null;
            } catch (CertificateException e) {
                return null;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (IOException e) {
                return null;
            }

            String resultString = Base64.encodeToString(encrypted, Base64.URL_SAFE);
            return resultString;
        }
    }

    /**
     * 解密
     */
    public static String decryptString(Context context, String data){
        //KeyStore
        KeyStore keyStore;
        //对称秘钥
        SecretKey secretKey;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
            } catch (KeyStoreException e) {
                return null;
            } catch (IOException e) {
                return null;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (CertificateException e) {
                return null;
            }

            try {
                secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
            } catch (KeyStoreException e) {
                return null;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (UnrecoverableKeyException e) {
                return null;
            }

            Cipher cipher;
            try {
                cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC
                        + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
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
            byte[] decrypted;
            try {
                decrypted = cipher.doFinal(Base64.decode(data.getBytes(), Base64.URL_SAFE));
            } catch (IllegalBlockSizeException e) {
                return null;
            } catch (BadPaddingException e) {
                return null;
            }

            String resultString = new String(decrypted);
            return resultString;

        }else {
            FileInputStream in = null;
            File file = new File(context.getFilesDir(),"keystore");
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

            try {
                keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(in,pas);
            } catch (KeyStoreException e) {
                return null;
            } catch (CertificateException e) {
                return null;
            } catch (NoSuchAlgorithmException e) {
                return null;
            } catch (IOException e) {
                return null;
            }

            try {
                KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry)
                        keyStore.getEntry("tttt", null);
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
                cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
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
            byte[] decrypted;
            try {
                decrypted = cipher.doFinal(Base64.decode(data.getBytes(), Base64.URL_SAFE));
            } catch (IllegalBlockSizeException e) {
                return null;
            } catch (BadPaddingException e) {
                return null;
            }

            String resultString = new String(decrypted);
            return resultString;
        }
    }
}
