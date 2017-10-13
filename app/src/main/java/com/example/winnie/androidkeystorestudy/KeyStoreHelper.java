package com.example.winnie.androidkeystorestudy;

import android.util.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by winnie on 2017/10/13.
 */

public class KeyStoreHelper {
    private static final String KEY_ALGORITHM = "DES";

    private String encodeFinalString;

    private KeyGenerator keyGenerator;
    private SecretKey key;
    public String encode() {

        //对称key即SecretKey创建和导入，假设双方约定使用DES算法来生成对称密钥
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        //设置密钥长度。注意，每种算法所支持的密钥长度都是不一样的。DES只支持64位长度密钥
        keyGenerator.init(64);

        //生成SecretKey对象，即创建一个对称密钥，并获取二进制的书面表达
        key = keyGenerator.generateKey();
        byte[] keyData = key.getEncoded();
        //日常使用时，一般会把上面的二进制数组通过Base64编码转换成字符串，然后发给使用者
        String keyInBase64 = Base64.encodeToString(keyData, Base64.DEFAULT);
        encodeFinalString = keyInBase64;

        return encodeFinalString;
    }

    private SecretKeySpec keySpec;
    private SecretKeyFactory secretKeyFactory;
    public String decode() {
        byte[] byteData = Base64.decode(encodeFinalString, Base64.DEFAULT);
        //假设对方收到了base64编码后的密钥，首先要得到其二进制表达式，用二进制数组构造KeySpec对象。对称key使用SecretKeySpec类
        keySpec = new SecretKeySpec(byteData, KEY_ALGORITHM);
        try {
            //创建对称Key导入用的SecretKeyFactory
            secretKeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        try {
            //根据KeySpec还原Key对象，即把key的书面表达式转换成了Key对象
            key = secretKeyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

        byte[] data = key.getEncoded();
        String keyInBase64 = Base64.encodeToString(data, Base64.DEFAULT);

        return keyInBase64;
    }
}
