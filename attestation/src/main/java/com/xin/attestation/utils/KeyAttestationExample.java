package com.xin.attestation.utils;

import android.util.Log;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class KeyAttestationExample {

    private static final String TAG = "KeyAttestationExample";

    private static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    private static final int ATTESTATION_VERSION_INDEX = 0;
    private static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
    private static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
    private static final int ATTESTATION_CHALLENGE_INDEX = 4;
    private static final int SW_ENFORCED_INDEX = 6;
    private static final int TEE_ENFORCED_INDEX = 7;

    // Some authorization list tags. The complete list is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    private static final int KM_TAG_PURPOSE = 1;
    private static final int KM_TAG_ALGORITHM = 2;
    private static final int KM_TAG_KEY_SIZE = 3;
    private static final int KM_TAG_USER_AUTH_TYPE = 504;
    private static final int KM_TAG_AUTH_TIMEOUT = 505;
    private static final int KM_TAG_ORIGIN = 702;
    private static final int KM_TAG_ROLLBACK_RESISTANT = 703;

    // The complete list of purpose values is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    private static final int KM_PURPOSE_SIGN = 2;

    // The complete list of algorithm values is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    private static final int KM_ALGORITHM_EC = 3;

    // Some authentication type values. The complete list is in this AOSP file:
    // hardware/libhardware/include/hardware/hw_auth_token.h
    private static final int HW_AUTH_PASSWORD = 1 << 0;
    private static final int HW_AUTH_FINGERPRINT = 1 << 1;

    // The complete list of origin values is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    private static final int KM_ORIGIN_GENERATED = 0;

    // Some security values. The complete list is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    private static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
    private static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;

    private static final int EXPECTED_ATTESTATION_VERSION = 1;


    // The Google root certificate that must have been used to sign the root
    // certificate in a real attestation certificate chain from a compliant device.
    // (Note, the sample chain used here is not signed with this certificate.)
    public static final String GOOGLE_ROOT_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV"
                    + "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy"
                    + "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B"
                    + "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS"
                    + "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7"
                    + "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj"
                    + "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq"
                    + "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ"
                    + "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O"
                    + "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg"
                    + "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi"
                    + "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M"
                    + "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E"
                    + "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um"
                    + "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD"
                    + "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO"
                    + "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk"
                    + "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD"
                    + "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB"
                    + "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m"
                    + "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY"
                    + "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm"
                    + "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u"
                    + "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD"
                    + "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy"
                    + "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD"
                    + "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic"
                    + "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1"
                    + "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n"
                    + "-----END CERTIFICATE-----";


    // mainEntrance
    public static boolean mainEntrance(X509Certificate[] certs) throws Exception {
        boolean verifyCertificateChainResult = verifyCertificateChain(certs);
        Log.wtf(TAG, String.format("verify certificate chain result=> %s", verifyCertificateChainResult ? "pass" : "not pass"));

        // Get the attestation extension data as an ASN.1 SEQUENCE.
        ASN1Sequence extensionData = extractAttestationSequence(certs[0]);

        // Use the attestation and keymaster security levels to determine whether the device has a Trusted Execution Environment (TEE)
        // and whether the attestation certificate was generated in that TEE. (attestation 生成的位置决定安全等级)
        int attestationSecurityLevel = getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX));
        int keymasterSecurityLevel = getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX));
        System.out.println("Attestation security level: " + securityLevelToString(attestationSecurityLevel));
        System.out.println("Keymaster security level: " + securityLevelToString(keymasterSecurityLevel));

        return verifyCertificateChainResult;
    }

    private static ASN1Sequence extractAttestationSequence(X509Certificate attestationCert) throws Exception, IOException {
        byte[] attestationExtensionBytes = attestationCert.getExtensionValue(KEY_DESCRIPTION_OID);
        if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
            throw new Exception("Couldn't find the keystore attestation " + "extension data.");
        }

        ASN1Sequence decodedSequence;
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(attestationExtensionBytes)) {
            // The extension contains one object, a sequence, in the
            // Distinguished Encoding Rules (DER)-encoded form. Get the DER
            // bytes.
            byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream.readObject()).getOctets();
            // Decode the bytes as an ASN1 sequence object.
            try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
                decodedSequence = (ASN1Sequence) seqInputStream.readObject();
            }
        }
        return decodedSequence;
    }

    private static ASN1Primitive findAuthorizationListEntry(ASN1Encodable[] authorizationList, int tag) {
        for (ASN1Encodable entry : authorizationList) {
            ASN1TaggedObject taggedEntry = (ASN1TaggedObject) entry;
            if (taggedEntry.getTagNo() == tag) {
                return taggedEntry.getObject();
            }
        }
        return null;
    }

    private static boolean verifyCertificateChain(X509Certificate[] certs) throws CertificateExpiredException, CertificateNotYetValidException,
            CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

        for (int i = 1; i < certs.length; ++i) {
            // Verify that the certificate has not expired.
            certs[i].checkValidity();

            if (i > 0) {
                // Verify previous certificate with the public key from this
                // certificate. If verification fails, the verify() method
                // throws an exception.
                PublicKey pubKey = certs[i].getPublicKey();
                certs[i - 1].verify(pubKey);
                if (i == certs.length - 1) {
                    // The last certificate (the root) is self-signed.
                    certs[i].verify(pubKey);
                }
            }
        }

        // If the attestation is trustworthy and the device ships with hardware-
        // level key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        X509Certificate secureRoot = (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes()));

        if (Arrays.equals(secureRoot.getTBSCertificate(), certs[certs.length - 1].getTBSCertificate())) {
            System.out.println("The root certificate is correct, so this attestation is trustworthy, as long as none of the certificates in the chain have been "
                    + "revoked. A production-level system should check the certificate revocation lists using the distribution points that are listed in the "
                    + "intermediate and root certificates.");
            return true;

        } else {
            System.out.println("The root certificate is NOT correct. The attestation was probably generated by software, not in secure hardware. This means "
                    + "that, although the attestation contents are probably valid and correct, there is no proof that they are in fact correct. If you're using "
                    + "a production-level system, you should now treat the properties of this attestation certificate as advisory only, and you "
                    + "shouldn't rely on this attestation certificate to provide security guarantees.");
            return false;
        }
    }

    public static X509Certificate[] loadCertificates(String[] certChain) throws CertificateException {
        // Load the attestation certificate chain.
        // The certificates below are retrieved from a software-generated sample.
        X509Certificate[] certs = new X509Certificate[certChain.length];
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < certChain.length; ++i) {
            certs[i] = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certChain[i].getBytes()));
        }
        return certs;
    }

    private static String securityLevelToString(int securityLevel) throws Exception {
        switch (securityLevel) {
            case KM_SECURITY_LEVEL_SOFTWARE:
                return "Software";
            case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                return "TEE";
            default:
                throw new Exception("Invalid security level.");
        }
    }

    private static int getIntegerFromAsn1(ASN1Encodable asn1Value) throws Exception {
        if (asn1Value instanceof ASN1Integer) {
            return KeyAttestationExample.bigIntegerToInt(((ASN1Integer) asn1Value).getValue());
        } else if (asn1Value instanceof ASN1Enumerated) {
            return KeyAttestationExample.bigIntegerToInt(((ASN1Enumerated) asn1Value).getValue());
        } else {
            throw new Exception("Integer value expected; found " + asn1Value.getClass().getName() + " instead.");
        }
    }

    static int bigIntegerToInt(BigInteger bigInt) throws Exception {
        if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0 || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new Exception("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }
}
