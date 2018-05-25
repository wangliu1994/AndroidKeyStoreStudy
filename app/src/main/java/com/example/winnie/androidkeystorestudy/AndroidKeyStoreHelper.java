package com.example.winnie.androidkeystorestudy;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
 * Created by winnie on 2017/10/12.
 */

public class AndroidKeyStoreHelper {
    private static final String KEY_STORE_TYPE = "AndroidKeyStore";
    private static final String KEY_NAME = "my_android_key_name";
    private static final String KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final int PURPOSE = KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT;

    private KeyStore keyStore;
    private FingerprintManager manager;

    private byte[] IV;

    private Context context;
    private EncryptListener encryptListener;
    private DecryptListener decryptListener;

    public void setEncryptListener(EncryptListener encryptListener) {
        this.encryptListener = encryptListener;
    }

    public void setDecryptListener(DecryptListener decryptListener) {
        this.decryptListener = decryptListener;
    }

    public AndroidKeyStoreHelper(FingerprintManager manager, Context context) {
        this.manager = manager;
        this.context = context;
        generateKey();
    }

    //生成key，使用 KeyGenerator 创建一个对称密钥，存放在 KeyStore 里。
    private void generateKey() {
        //这里使用AES + CBC + PADDING_PKCS7，并且需要用户验证方能取出，这里生成加密content的key
        try {
            keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);

            KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM, KEY_STORE_TYPE);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_NAME, PURPOSE);
            builder.setUserAuthenticationRequired(true);
            builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC);
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true);
            }
            generator.init(builder.build());
            generator.generateKey();
            Log.d("TAG", "生成加密密钥成功");
        } catch (Exception e) {
            Log.d("TAG", "生成加密密钥失败");
            e.printStackTrace();
        }
    }

    //使用刚才创建好的密钥，初始化Cipher对象:
    private Cipher getEncryptCipher() {
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME, null);
            if (key == null) {
                return null;
            }
            final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                    + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher;

        } catch (CertificateException
                | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    //加密content
    public void encrypt(final String content) {
        if (ActivityCompat.checkSelfPermission(context,
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        Cipher cipher = getEncryptCipher();
        if (cipher == null) {
            return;
        }

        //直接加密
        try {
            byte[] encrypted = cipher.doFinal(content.getBytes());
            IV = cipher.getIV();
            String resultString = Base64.encodeToString(encrypted, Base64.URL_SAFE);
            if (encryptListener != null) {
                encryptListener.onEncryptSuccess(new String(resultString));
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        //指纹授权之后加密
//        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
//        manager.authenticate(cryptoObject, null, 0, new FingerprintManager.AuthenticationCallback() {
//            @Override
//            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
//                Cipher cipherNew = result.getCryptoObject().getCipher();
//                try {
//                    byte[] encrypted = cipherNew.doFinal(content.getBytes());
//                    IV = cipherNew.getIV();
//                    String resultString = Base64.encodeToString(encrypted, Base64.URL_SAFE);
//                    if (encryptListener != null) {
//                        encryptListener.onEncryptSuccess(new String(resultString));
//                    }
//                } catch (IllegalBlockSizeException | BadPaddingException e) {
//                    e.printStackTrace();
//                }
//            }
//
//            @Override
//            public void onAuthenticationError(int errorCode, CharSequence errString) {
//                if (encryptListener != null) {
//                    encryptListener.onEncryptFailed(errString.toString());
//                }
//            }
//
//            @Override
//            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
//                if (encryptListener != null) {
//                    encryptListener.onEncryptFailed(helpString.toString());
//                }
//            }
//
//            @Override
//            public void onAuthenticationFailed() {
//                if (encryptListener != null) {
//                    encryptListener.onEncryptFailed("指纹未通过。再试一次");
//                }
//            }
//        }, new Handler());

    }

    private Cipher getDecryptCipher() {
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME, null);

            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES +
                    "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
            return cipher;
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }

    //解密
    public void decrypt(final String content) {
        if (ActivityCompat.checkSelfPermission(context,
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        Cipher cipher = getDecryptCipher();
        if (cipher == null) {
            return;
        }

        //直接解密
        try {
            byte[] encrypted = cipher.doFinal(Base64.decode(content.getBytes(), Base64.URL_SAFE));
            if (decryptListener != null) {
                decryptListener.onDecryptSuccess(new String(encrypted));
            }

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        //指纹授权之后解密
//        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
//        manager.authenticate(cryptoObject, null, 0, new FingerprintManager.AuthenticationCallback() {
//            @Override
//            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
//                Cipher cipher1 = result.getCryptoObject().getCipher();
//                try {
//                    byte[] encrypted = cipher1.doFinal(Base64.decode(content.getBytes(), Base64.URL_SAFE));
//                    if (decryptListener != null) {
//                        decryptListener.onDecryptSuccess(new String(encrypted));
//                    }
//
//                } catch (IllegalBlockSizeException | BadPaddingException e) {
//                    e.printStackTrace();
//                }
//            }
//
//            @Override
//            public void onAuthenticationError(int errorCode, CharSequence errString) {
//                if (decryptListener != null) {
//                    decryptListener.onDecryptFailed(errString.toString());
//                }
//            }
//
//            @Override
//            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
//                if (decryptListener != null) {
//                    decryptListener.onDecryptFailed(helpString.toString());
//                }
//            }
//
//            @Override
//            public void onAuthenticationFailed() {
//                if (decryptListener != null) {
//                    decryptListener.onDecryptFailed("指纹未通过。再试一次");
//                }
//            }
//        }, new Handler());
    }

    public interface EncryptListener {
        void onEncryptSuccess(String encryptCode);

        void onEncryptFailed(String msg);
    }

    public interface DecryptListener {
        void onDecryptSuccess(String decryptCode);

        void onDecryptFailed(String msg);
    }
}
