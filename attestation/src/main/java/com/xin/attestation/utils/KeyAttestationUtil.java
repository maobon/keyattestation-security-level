package com.xin.attestation.utils;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyAttestationUtil {

    private static final String aTag = "KeyAttestationUtil";

    public static byte TAG_ASN1_INT = 0X02;
    public static byte TAG_ASN1_SEQUENCE = 0X30;
    public static byte TAG_ASN1_OCTETSTRING = 0X04;
    public static byte TAG_ASN1_ENUM = 0X0A;

    /**
     * 解析attestation
     */
    public static KeyDescription verifyAttestationExtension(byte[] extension) {
        KeyDescription description = new KeyDescription();
        try {
            if (extension == null || extension.length == 0) {
                return null;
            }
            ByteBuffer bufStream = ByteBuffer.wrap(extension);
            bufStream.order(ByteOrder.LITTLE_ENDIAN);

            // verify root
            byte rootTag = bufStream.get();
            int rootLength = getASN1Length(bufStream);
            if (!(rootTag == TAG_ASN1_OCTETSTRING && bufStream.hasRemaining() && bufStream.remaining() == rootLength)) {
                Log.e(aTag, "is not attestation extension by root , maybe not der");
                return null;
            }

            // verify root sequence
            byte rootSequenceTag = bufStream.get();
            int rootSequenceLength = getASN1Length(bufStream);
            if (!(rootSequenceTag == TAG_ASN1_SEQUENCE && bufStream.hasRemaining())) {
                Log.e(aTag, "is not attestation extension by root sequence");
                return null;
            }

            // verify attestation version
            byte attestationVersionTag = bufStream.get();
            int attestationVersionLength = getASN1Length(bufStream);
            byte[] attestationVersionValue = new byte[attestationVersionLength];
            bufStream.get(attestationVersionValue);
            if (!(attestationVersionTag == TAG_ASN1_INT)) {
                Log.e(aTag, "is not attestion extension by attestation version");
                return null;
            }
            description.setAttestationVersion(attestationVersionValue[0] & 0xff);

            // verify attestation security
            byte attestationSecurityTag = bufStream.get();
            int attestationSecurityLength = getASN1Length(bufStream);
            byte[] attestationSecurityValue = new byte[attestationSecurityLength];
            bufStream.get(attestationSecurityValue);
            if (!(attestationSecurityTag == TAG_ASN1_ENUM)) {
                Log.e(aTag, "is not attestion extension by tmp1");
                return null;
            }
            description.setAttestationSecurityLevel(attestationSecurityValue[0] & 0xff);

            // verify keymaster version
            byte keymasterVersionTag = bufStream.get();
            int keymasterVersionLength = getASN1Length(bufStream);
            if (keymasterVersionLength != 0) {
                byte[] keymasterVersionValue = new byte[keymasterVersionLength];
                bufStream.get(keymasterVersionValue);
                if (!(keymasterVersionTag == TAG_ASN1_INT)) {
                    Log.e(aTag, "is not attestion extension by tmp2");
                    return null;
                }
                description.setKeymasterVersion(keymasterVersionValue[0] & 0xff);
            }

            // -------------- keymaster 的安全等级 att认证器需要 keymaster安全等级必须为TEE ------------
            // verify keymaster security
            byte keymasterSecurityTag = bufStream.get();
            int keymasterSecurityLength = getASN1Length(bufStream);
            byte[] keymasterSecurityValue = new byte[keymasterSecurityLength];
            bufStream.get(keymasterSecurityValue);
            if (!(keymasterSecurityTag == TAG_ASN1_ENUM)) {
                Log.e(aTag, "is not attestion extension by keymaster security");
                return null;
            }
            description.setKeymasterSecurityLevel(keymasterSecurityValue[0] & 0xff);
            // --------------

            // verify challenge
            byte challengeTag = bufStream.get();
            int challengeLength = getASN1Length(bufStream);
            if (challengeLength != 0) {
                byte[] challengeValue = new byte[challengeLength];
                bufStream.get(challengeValue);
                if (!(challengeTag == TAG_ASN1_OCTETSTRING)) {
                    Log.e(aTag, "is not attestion extension by challenge");
                    return null;
                }
                description.setAttestationChallenge(challengeValue);
            }

            // verify tmp
            byte tmp2Tag = bufStream.get();
            int tmp2Length = getASN1Length(bufStream);
            if (tmp2Length != 0) {
                byte[] tmp2Value = new byte[tmp2Length];
                bufStream.get(tmp2Value);
                if (!(tmp2Tag == TAG_ASN1_OCTETSTRING)) {
                    Log.e(aTag, "is not attestion extension by tmp2");
                    return null;
                }
            }

            // verify swenforced
            byte swTag = bufStream.get();
            int swLength = getASN1Length(bufStream);
            if (swLength != 0) {
                byte[] swValue = new byte[swLength];
                bufStream.get(swValue);
                if (!(swTag == TAG_ASN1_SEQUENCE)) {
                    Log.e(aTag, "is not attestion extension by sw");
                    return null;
                }
            }

            // verify tee
            byte teeTag = bufStream.get();
            int teeLength = getASN1Length(bufStream);
            if (teeLength != 0) {
                byte[] teeValue = new byte[teeLength];
                bufStream.get(teeValue);
                if (!(teeTag == TAG_ASN1_SEQUENCE)) {
                    Log.e(aTag, "is not attestion extension by tee");
                    return null;
                }
            }
            return description;
        } catch (Exception e) {
            Log.e(aTag, "verifyAttestionExtension:" + e.getMessage());
        }
        return null;

    }

    private static int getASN1Length(ByteBuffer buf) {
        Log.d(aTag, "getASN1Length");
        byte tmpLength = buf.get();
        if ((tmpLength & 0x80) == 0) {
            return tmpLength;
        } else {
            int lengthLength = (int) (tmpLength & 0x7f);
            if (lengthLength > 4) {
                // extension der will not be large than 65535
                return -1;
            }
            byte[] tmpLengths = new byte[lengthLength];
            buf.get(tmpLengths);
            return byteArrayToInt(tmpLengths);
        }
    }

    private static int byteArrayToInt(byte[] b) {
        int length = b.length;
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = value | ((b[i] & 0xff) << (length - 1 - i) * 8);
        }
        return value;
    }

    public static Certificate[] exportKeyAttestation(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            return ks.getCertificateChain(alias);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString
                        .replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                // byte[] certificateData = Base64.getDecoder().decode(certificateString);
                byte[] certificateData = Base64.decode(certificateString, Base64.DEFAULT | Base64.NO_PADDING | Base64.NO_WRAP);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }

}
