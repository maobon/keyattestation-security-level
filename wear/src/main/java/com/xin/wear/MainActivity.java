package com.xin.wear;

import android.os.Bundle;
import android.support.wearable.activity.WearableActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.xin.attestation.AttestationSdk;

import java.util.UUID;

public class MainActivity extends WearableActivity {

    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        // Enables Always-on
        setAmbientEnabled();

        Button button = findViewById(R.id.btn_test);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                UUID uuid = UUID.randomUUID();
                String keyAlias = uuid.toString();

                boolean result = AttestationSdk.generateKeyPair(keyAlias, MainActivity.this);
                Log.wtf(TAG, "generate keypair result= " + result);

                AttestationSdk.getKeyStoreSecurityLevel(keyAlias);

                AttestationSdk.keyAttestationVerify(keyAlias);
            }
        });
    }
}
