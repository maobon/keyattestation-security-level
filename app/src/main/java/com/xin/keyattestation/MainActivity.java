package com.xin.keyattestation;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import com.xin.attestation.AttestationSdk;

import java.util.List;
import java.util.UUID;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String TAG = "MainActivity";

    private String keyAlias;
    public static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
    }

    private void initViews() {
        findViewById(R.id.btn_generate_keypair_ecc).setOnClickListener(this);
        findViewById(R.id.btn_generate_keypair_rsa).setOnClickListener(this);

        findViewById(R.id.btn_get_keystore_security_level).setOnClickListener(this);
        findViewById(R.id.btn_verify_android_key_attestation).setOnClickListener(this);

        findViewById(R.id.btn_list_key_alias).setOnClickListener(this);
        findViewById(R.id.btn_import_private_key).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btn_generate_keypair_ecc:
                UUID uuid = UUID.randomUUID();
                this.keyAlias = uuid.toString();
                boolean result = AttestationSdk.generateKeyPair(this.keyAlias, this);
                Log.wtf(TAG, "generate keypair result= " + result);
                break;

            case R.id.btn_generate_keypair_rsa:
                UUID uuid2 = UUID.randomUUID();
                this.keyAlias = uuid2.toString();

                boolean result2 = AttestationSdk.generateKsRsaKeyPair("GMRZ-TEST", this);
                Log.wtf(TAG, "generate keypair result= " + result2);

                break;

            case R.id.btn_get_keystore_security_level:
                AttestationSdk.getKeyStoreSecurityLevel(keyAlias);
                break;

            case R.id.btn_verify_android_key_attestation:
                AttestationSdk.keyAttestationVerify(keyAlias);
                break;

            case R.id.btn_list_key_alias:
                List<String> strings = AttestationSdk.listKeyStoreAllKeyAlias();
                for (String name : strings) {
                    Log.wtf(TAG, "key alias name= " + name);
                }
                break;

            case R.id.btn_import_private_key:
                AttestationSdk.importDeviceCertificate("GMRZ-TEST");
                break;
        }
    }
}
