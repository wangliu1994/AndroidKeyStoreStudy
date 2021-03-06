package com.example.winnie.androidkeystorestudy;

import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.example.winnie.androidkeystorestudy.sample.SampleActivity;

public class MainActivity extends AppCompatActivity {

    private EditText passwordEdit;
    private TextView encryptText;
    private TextView decryptText;

    private EditText passwordEdit1;
    private TextView encryptText1;
    private TextView decryptText1;

    private String encryptString;

    private AndroidKeyStoreHelper helper;
    private KeyStoreHelper keyStoreHelper;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        passwordEdit = (EditText) findViewById(R.id.password);
        encryptText = (TextView) findViewById(R.id.encrypt_text);
        decryptText = (TextView) findViewById(R.id.decrypt_text);

        passwordEdit1 = (EditText) findViewById(R.id.password1);
        encryptText1 = (TextView) findViewById(R.id.encrypt_text1);
        decryptText1 = (TextView) findViewById(R.id.decrypt_text1);

//        FingerprintManager manager = getSystemService(FingerprintManager.class);
//        helper = new AndroidKeyStoreHelper(manager, MainActivity.this);
//        helper.setEncryptListener(new AndroidKeyStoreHelper.EncryptListener() {
//            @Override
//            public void onEncryptSuccess(String encryptCode) {
//                encryptString = encryptCode;
//                encryptText.setText("加密成功 encrypt code-> " + encryptCode);
//            }
//
//            @Override
//            public void onEncryptFailed(String msg) {
//                encryptText.setText(msg);
//            }
//
//        });
//        helper.setDecryptListener(new AndroidKeyStoreHelper.DecryptListener() {
//            @Override
//            public void onDecryptSuccess(String decryptCode) {
//                decryptText.setText("解密成功 decrypt code-> " + decryptCode);
//            }
//
//            @Override
//            public void onDecryptFailed(String msg) {
//                decryptText.setText(msg);
//            }
//        });

//        keyStoreHelper = new KeyStoreHelper();
        findViewById(R.id.encode_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String password = passwordEdit.getText().toString();
                if(password == null || password.length()==0){
                    Toast.makeText(MainActivity.this, "please input your password", Toast.LENGTH_SHORT).show();
                }else {
                    encryptText.setText("验证指纹中....");
                    helper.encrypt(password);
                }
//                encryptText.setText(keyStoreHelper.encode());
            }
        });

        findViewById(R.id.decode_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(encryptString == null || encryptString.length()==0){
                    Toast.makeText(MainActivity.this, "please encrypt your password first", Toast.LENGTH_SHORT).show();
                }else {
                    decryptText.setText("验证指纹中....");
                    helper.decrypt(encryptString);
                }
//                decryptText.setText(keyStoreHelper.decode());
            }
        });

        findViewById(R.id.sample_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, SampleActivity.class);
                startActivity(intent);
            }
        });



        findViewById(R.id.encode_button1).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String password = passwordEdit1.getText().toString();
                encryptString = LoginKeyStoreUtils.encryptString(MainActivity.this, password);
                encryptText1.setText(encryptString);
            }
        });

        findViewById(R.id.decode_button1).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                decryptText1.setText(LoginKeyStoreUtils.decryptString(MainActivity.this, encryptString));
            }
        });
    }
}
