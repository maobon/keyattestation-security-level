package com.xin.attestation;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.xin.attestation.utils.KeyASecurityType;
import com.xin.attestation.utils.KeyAttestationExample;
import com.xin.attestation.utils.KeyAttestationUtil;
import com.xin.attestation.utils.KeyDescription;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class AttestationSdk {

    private static final String TAG = "AttestationSdk";

    private static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    public static boolean generateKeyPair(String keyAlias, Context context) {
        //Calendar notBefore = Calendar.getInstance();
        //Calendar notAfter = Calendar.getInstance();
        //notAfter.add(Calendar.YEAR, 20);

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("prime256v1"))
                    .setUserAuthenticationRequired(false);

            //.setCertificateSubject(new X500Principal(String.format("CN=%s, OU=%s", keyAlias, context.getPackageName())))
            //.setCertificateSerialNumber(BigInteger.ONE)
            //.setCertificateNotBefore(notBefore.getTime())
            //.setCertificateNotAfter(notAfter.getTime());

            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
                // require API Level >= 24
                builder.setAttestationChallenge(genChallenge());
            }

            generator.initialize(builder.build());
            generator.generateKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static boolean generateKsRsaKeyPair(String keyUUID) {

        try {
            KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyUUID, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setKeySize(2048)
                    .setUserAuthenticationRequired(false);

            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
                // require API Level >= 24
                builder.setAttestationChallenge(genChallenge());
            }

            kpGenerator.initialize(builder.build());
            kpGenerator.generateKeyPair();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    // 做证书导入操作
    public static void importDeviceCertificate(Context context, String keyAlias) {

        final String dataToBeSigned = "dataToBeSigneddataToBeSigneddataToBeSigneddataToBeSigneddataToBeSigned";

        try {
            Signature signature = Signature.getInstance("SHA256withRSA");

            // 用私钥对数据进行签名
            /*final PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(RSA_PRI_KEY, Base64.DEFAULT)));*/

            // open from raw
            // 从资源文件中读取私钥 注意没有-----BEGIN PRIVATE KEY-----和-----END PRIVATE KEY-----
            InputStream in = context.getResources().openRawResource(R.raw.pri_key);

            ByteArrayOutputStream os = new ByteArrayOutputStream();

            byte[] buffer = new byte[1024];
            int len;
            while ((len = in.read(buffer)) != -1) {
                os.write(buffer, 0, len);
            }

            byte[] priBytes = Base64.decode(os.toByteArray(), Base64.DEFAULT);

            final PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(priBytes));

            signature.initSign(privateKey);
            signature.update(dataToBeSigned.getBytes());
            byte[] signRet = signature.sign();

            Log.wtf(TAG, "use private key signRet ret = " + bytesToHexStr(signRet));

            // 字符串公钥转化为公钥 进行验签
            /*byte[] byteKey = Base64.decode(RSA_PUB_KEY.getBytes(), Base64.DEFAULT);
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(X509publicKey);

            signature.initVerify(pub);
            signature.update(dataToBeSigned.getBytes());
            boolean verify1 = signature.verify(signRet);*/

            // 字符串证书转化为证书
            /*Certificate cert = CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.decode(RSA_CERT, Base64.DEFAULT)));*/

            // 从资源文件中读取
            InputStream is = context.getResources().openRawResource(R.raw.certificate);
            Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(is);

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            //Certificate[] certChain = keyStore.getCertificateChain(keyAlias); // 导出一条证书链 里面公钥不对应导入私钥


            // *** 私钥 导入 ***
            // priKey and cert chain
            keyStore.setEntry(
                    keyAlias,
                    new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{cert}), // 导入的证书不强制要求与该私钥对应 不对应也可以
                    null
            );

            // 私钥
            // 可以用于签名加密等 但是android ks私钥不能被导出
            //Key key = keyStore.getKey(keyAlias, null);

            // priKey from ks signRet
            /*signature.initSign((PrivateKey) key);
            signature.update(dataToBeSigned.getBytes());
            byte[] sig = signature.sign();
            Log.wtf(TAG, "get priKey from ks and signRet result = " + bytesToHexStr(sig));*/

            // 公钥来自导入证书 从keystore中取出
            // 用公钥对被签名数据验签
            Certificate certificate = keyStore.getCertificate(keyAlias);
            PublicKey publicKey = certificate.getPublicKey();

            signature.initVerify(publicKey);
            signature.update(dataToBeSigned.getBytes());
            boolean verify = signature.verify(signRet);
            Log.wtf(TAG, "verify sig ret = " + verify);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 列出keystore中所有秘钥的别名
    public static List<String> listKeyStoreAllKeyAlias() {
        List<String> list = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String keyAlias = aliases.nextElement();
                list.add(keyAlias);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    public static void getKeyStoreSecurityLevel(String keyAlias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            Certificate[] certificateChain = ks.getCertificateChain(keyAlias);
            X509Certificate certificate = (X509Certificate) certificateChain[0];

            byte[] extensionValue = certificate.getExtensionValue(KEY_DESCRIPTION_OID);
            KeyDescription keyDescription = KeyAttestationUtil.verifyAttestationExtension(extensionValue);
            if (keyDescription == null) {
                Log.wtf(TAG, "keyDescription is null");
                return;
            }

            KeyASecurityType attestationSecurityLevel = keyDescription.getAttestationSecurityLevel();
            Log.wtf(TAG, "attestationSecurityLevel= " + attestationSecurityLevel);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean keyAttestationVerify(String keyAlias) {
        boolean result = false;
        try {
            Certificate[] certificates = KeyAttestationUtil.exportKeyAttestation(keyAlias);
            if (certificates == null)
                return result;

            X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
            int index = 0;
            for (Certificate cert : certificates) {
                String strPEM = Base64.encodeToString(cert.getEncoded(), Base64.DEFAULT | Base64.NO_WRAP | Base64.NO_PADDING);
                x509Certificates[index] = KeyAttestationUtil.convertToX509Cert(strPEM);
                index++;
            }
            result = KeyAttestationExample.mainEntrance(x509Certificates);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }


    /**
     * 挑战值
     */
    private static byte[] genChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return challenge;
    }

    //
    private static String bytesToHexStr(byte[] paramArrayOfByte) {
        if (paramArrayOfByte == null) {
            return null;
        }
        StringBuilder localStringBuilder = new StringBuilder();
        byte[] arrayOfByte;
        int i = (arrayOfByte = paramArrayOfByte).length;
        for (int j = 0; j < i; j++) {
            String str;
            if ((str = Integer.toHexString(arrayOfByte[j] & 0xFF)).length() == 1) {
                localStringBuilder.append("0");
            }
            localStringBuilder.append(str);
        }
        return localStringBuilder.toString();
    }

    private static byte[] hexToByte(String hex) {
        int m = 0, n = 0;
        int byteLen = hex.length() / 2; // 每两个字符描述一个字节
        byte[] ret = new byte[byteLen];
        for (int i = 0; i < byteLen; i++) {
            m = i * 2 + 1;
            n = m + 1;
            int intVal = Integer.decode("0x" + hex.substring(i * 2, m) + hex.substring(m, n));
            ret[i] = Byte.valueOf((byte) intVal);
        }
        return ret;
    }


    // 私钥
    private static final String RSA_PRI_KEY =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDEMBB24ccG2b9k" +
                    "v7bI3u/LTHaI9frrJ4KLjQ0kA6MipzwofvE1d79zeZVdS+oMahsygDFpUN6Nij94" +
                    "2AJCwbEG8OBvXCNbps5XgyT9P/JN+ZBNUjZxntPA8DbUiVFx2OVwHI7BQGtL8YIi" +
                    "DqZ/lhsW4seMC/UAB9YYal4LxzgE41nafA0x0haz1oaiZUgAsjddXV1BMH/ohu6m" +
                    "UZ0VW5C5GCTRFrHbm0VK8UWmVl5n2GzfUfwykNBZGWGXEqqppWquMcKWkV1cRH6b" +
                    "KTX+6KcwFHE8S2yL1wN8hiLTHo081o0Um8pMOsDM2K/CB7N8nO1Pfzej1pMiW6Mn" +
                    "dAoevup7AgMBAAECggEBAIE+QLpwhpMGw8V1Xs75vvMpDjWwBnr/7kpMw8lj9AaS" +
                    "MVlkNzdICgHiqPlrV2aSSBR+yw5cTiDkYGgVtXeQ7jRqXxA9nLV2MB0KskV76P5h" +
                    "WCT38hHr1ggWt6hQRi0/+/ZdedXpwEWpdldFW35VvsbW4yppfh9lCi/PcuFDfq4I" +
                    "h8wcJvw/d+sIhvidFZh1pCb6GVM20HIjy/TD1HkJ2FHqcePApihtDt1aRuN/7PSP" +
                    "SxipP2DEcY1kzmUxGOZPc+twXT4LOqao9KGhksUyEgAb89lAkuHVeh4skH9Gvk+5" +
                    "BwcpPp9mnkgRpiJX0g+h8LCGTmCN8did+nQfkXOmnZECgYEA9f2v+45iH3VqzKrL" +
                    "zPINNt/h45kLYa6UzPq5g1dohXTb3BK1aZVFQlIqkwZv2nY7KcBDR2P4ISclZ6ko" +
                    "lf0GOAlxuz5fg1H3rsESWxA1fHzDNdNQeoBrkJjGnU4u2uNxMkEEyezssJbx/B6X" +
                    "jECjig3Zwg+W3lRcWhsc/cdxtc8CgYEAzCucvrrYJWJZ1MkTjk6axp1Yj4FRXbCk" +
                    "GUtlMcZnKL/ZW40FCyu9rNx5TfeChIisMdfRhoh8tQTT0+vamq80fUFJfno9NWD6" +
                    "z6uo/bvnIDRFsYrMsdNlTl2zsbTyLXpzakQMCgKDSdFEJjtdJxtozQ9AZ0u3pU04" +
                    "s0G3m0s9l5UCgYBMvGKVeokpfxtd1TnWKPvuTlDNCwT959QLTXtpeW7lktqzADMP" +
                    "SL1ePvuA+dUStScnkw5pysmwreGBQMekYlX6TRfpbT+mW3+ESD5NofTNbK4IsG6+" +
                    "iCkF5mKu16DOL300TAwOYZZEUBIUsAZefhuGCWQQoYRSvsZAZYzZrcnPCQKBgC+h" +
                    "aQLR4gTuqdhLRIWpbtAw+u0XlRzPTakc/rGbAIvwHcwO3QNbI/fEw4Pd3xP+MnW6" +
                    "TIYfJ0CvrJ8+4ZO+lfc2mOepqsfeJQT3ngf7oxLPPwcJQ3GkyHh8waQOe4UCkRRU" +
                    "ZZ6cMXayHDzzEmtCKLPWAAdZEbG9jyG6jhPrfKX1AoGBAKBKqbwa38MXDep84cew" +
                    "5Cb9L/kmSDhBUWSrazWAr2cyeJZNJ/fzCfDH1ANrdVr17x5cKVLV+pOTgvNIUhV5" +
                    "EDYkcqb3nJ3H08Onku1geSWpD49AyU/qJNfQxSWFur0Hn2Mro1qYzAmRdJ2WfJKh" +
                    "QJxwEuDc9p69ThQasXSWXbqL";

    // 证书 - 对应上面的 private key
    private static final String RSA_CERT =
            "MIIDjDCCAnQCCQDabW5RdpJCbDANBgkqhkiG9w0BAQUFADCBhzELMAkGA1UEBhMC" +
                    "Q04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWppbmcxDjAMBgNVBAoM" +
                    "BVhJTllJMQswCQYDVQQLDAJJVDEVMBMGA1UEAwwMd3d3LmdtcnouY29tMSAwHgYJ" +
                    "KoZIhvcNAQkBFhF4aW55aUBnbXJ6LWJqLmNvbTAeFw0yMDAxMTkxMDAyMzFaFw0y" +
                    "NDEyMjMxMDAyMzFaMIGHMQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQ" +
                    "MA4GA1UEBwwHQmVpamluZzEOMAwGA1UECgwFWElOWUkxCzAJBgNVBAsMAklUMRUw" +
                    "EwYDVQQDDAx3d3cuZ21yei5jb20xIDAeBgkqhkiG9w0BCQEWEXhpbnlpQGdtcnot" +
                    "YmouY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxDAQduHHBtm/" +
                    "ZL+2yN7vy0x2iPX66yeCi40NJAOjIqc8KH7xNXe/c3mVXUvqDGobMoAxaVDejYo/" +
                    "eNgCQsGxBvDgb1wjW6bOV4Mk/T/yTfmQTVI2cZ7TwPA21IlRcdjlcByOwUBrS/GC" +
                    "Ig6mf5YbFuLHjAv1AAfWGGpeC8c4BONZ2nwNMdIWs9aGomVIALI3XV1dQTB/6Ibu" +
                    "plGdFVuQuRgk0Rax25tFSvFFplZeZ9hs31H8MpDQWRlhlxKqqaVqrjHClpFdXER+" +
                    "myk1/uinMBRxPEtsi9cDfIYi0x6NPNaNFJvKTDrAzNivwgezfJztT383o9aTIluj" +
                    "J3QKHr7qewIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBl+KJtQZMazrBvICy2P1Pe" +
                    "/ykM6EfKvY2cQ4Rq/gSH8QR59ZKivfFCrIgKX8pTjXem7+a1Biq3l91fpoiOhHWG" +
                    "2fu1AfytIHfZFQ1fA2rdNn0CUur3SzRoRjItSNl7BfzKASl6u+9FJGPdNz5peng2" +
                    "GNO7NMjDTktWv1oS4hYR8MZtFFju/LxinpAq/9Ih71LhCr3DeR+GQpjPMEpbTIIP" +
                    "E7YHqSCi6GP6aWZvfwZGxQ6fsF58T6POLLz8mfSSPENA88xRk8CF8we4mlwL4R/4" +
                    "8QOKUv7iSjGM+GYeWfdGwf5u4SnZPT5RSvRDW/7t0Ay7ivzESHd00FSrJev79MI/";

    // 来自huhu PKCS8 私钥
    private static final String RSA_PRI_KEY_HUHU =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAfuyGBpjgD1rQ" +
                    "NDHp2e9ZU9VFuhXS6I6xahRueNzlbV0YBhUl91d7BihqKRqZcsa3SoECd4kZOD52" +
                    "RKaDEKzT89Nx+NJbvL0ir6ZVgJI4Vf7R5LlEnZ+IvqzloTJbqu5g8o5maQs5pfC0" +
                    "66urbAGRgfKsXM0CT+aR2x7TW92CtlGncBZ7o7rpr8Ult7yhAqN9vKPk/iIgIHcL" +
                    "alL1kP5FYtT3THylh2I6frsU5sQ77bbAhVDGNE1aJiiH9Tk10epjRc7oGUGtsr4O" +
                    "5adIEkmtW9RsuC1y4pesI15nRtm8zoBU+ZbBQd8fiIHE5WevsxUml/TQEpEomdz8" +
                    "9uhcv96pAgMBAAECggEAYeTqgmp+eow0gefZbnT/zSzeLFyrVpwgXUd2Zowewqqw" +
                    "ilQlky5LlewWx45p0ZnWR0ajf06tMV8yHNFi4Qqs6gl5AeApkq/Ue/xaGeeN9Qp+" +
                    "0d2A/s0uYcuegBVPV+EA49rW4mwPYlzqogesQTxnO8mbUV7Mf52Ew65s6c4xQ5R0" +
                    "cC7dp7YQW0oQpfLfRH3OvycUH3EXW9dVpKKq/iUvaqzJCUQqaTD4/BvOWcTNIaEr" +
                    "wHjwrGbDmV0kvRWa6Wa92uccSrZV6kbw+4PvRBDnlRgBegeiJ4zvsgB+lsmecEyo" +
                    "Mb53bvsyjzrY5Kncij51n06p6gbZxmiolqX9pX+xFQKBgQDuGrsVmOBKRS+ONU27" +
                    "79k88pCP1rt+vprABM35Tnjof4fJXi6YTzYnYrdCSa2yeu9U71zB+BOYvz0Shitk" +
                    "q8X8dh587CY3WQY9+9tWvXXoHSpdJ8n+gpg8vNX20AwpArvvTHMDU9VGfpkItGfv" +
                    "9K4L/rdTQLzcD9HFL0zubfjx1wKBgQDO9qgKB4jXVbauWQpnQO0oGuh13I4POQHl" +
                    "ybiYmZTzYtiU+O2QychmMZ4lAU29XARW8YdNRK48TekT1tVn0I2bEQYs3P9wuqfS" +
                    "EMZomSw32v5ztnJw6MkRFxK3n+RO3x4D3mvKd04HhBUd1VFM5oZcnJKbFlKNUpXh" +
                    "32sBVVyjfwKBgFfF1NeGTpAyZvB2Z9xy81MLXA0aLG3xl5xXaRKRQfL7KDQsGuMc" +
                    "uCrWshWmkXhs5xMZVclPSPIS9VGB0jc/NzH03RJR/1iB4dIxqM6V8wQI1FgY1daT" +
                    "j8k8F2fvk7v+fQce2HsOiV1+R620y2fie9KCKFRxVe2Ni1e0Mxjlw1JrAoGBAMzc" +
                    "PHNJB/vWXTBw9KpGCzoCgI2B1qBc1nMFXJK4m0bbVfUH/eeuxI3bmWWZx8CjX6xM" +
                    "AZjLXghVOlwn8C+FsVWH4WvxCWwlZs65ShvpWmqje/E/7EG1OqmPBDj8rPohQk2k" +
                    "EWBk/bjU1i4kpAgRu3faiAe5bddzoubkxr+YJk2zAoGBAJnSQyi1MxCCg3sWPVqd" +
                    "796q/Cu8bzsMg30rN/mxZ6uTud256VAN++4dneXco+Jv/OuXUEkH6gbzDB4MMg+p" +
                    "4wlPNGlBjZeyV2JpfbZUgksF3WqbIqsSh8idNsibyIwknMmqWHAy4FPgpPkJsjV8" +
                    "RBMdZQTkuv3dmEWeH48Q5jpX";

}
