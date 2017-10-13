package com.example.winnie.androidkeystorestudy.sample;

import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.example.winnie.androidkeystorestudy.R;

/**
 * 加密content 并将加密后的数据存储在SharedPreferences中
 */
public class SampleActivity extends AppCompatActivity implements View.OnClickListener,FingerprintHelper.SimpleAuthenticationCallback {

    private Button encrypt, decrypt;
    private TextView tv;
    private FingerprintHelper helper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample);
        encrypt = (Button) findViewById(R.id.encrypt);
        decrypt = (Button) findViewById(R.id.decrypt);
        tv = (TextView) findViewById(R.id.tv);
        encrypt.setOnClickListener(this);
        decrypt.setOnClickListener(this);
        helper = new FingerprintHelper(this);
        helper.setCallback(this);
        helper.generateKey();
        tv.setText("已生成Key");
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.encrypt:
                helper.setPurpose(KeyProperties.PURPOSE_ENCRYPT);
                tv.setText("开始验证指纹......");
                helper.authenticate();
                break;
            case R.id.decrypt:
                helper.setPurpose(KeyProperties.PURPOSE_DECRYPT);
                tv.setText("开始验证指纹......");
                helper.authenticate();
                break;
        }
    }

    @Override
    public void onAuthenticationSucceeded(String value) {
        tv.setText(value);
    }

    @Override
    public void onAuthenticationFail() {
        tv.setText("验证失败");
    }
}
