package com.xin.attestation.utils;

/**
 * Created by zhangchao on 1/9/18.
 */

public class KeyDescription {

	public static final int ATTESTATION_VERSION_INDEX = 0;
	public static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
	public static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
	public static final int ATTESTATION_CHALLENGE_INDEX = 4;
	public static final int SW_ENFORCED_INDEX = 6;
	public static final int TEE_ENFORCED_INDEX = 7;

	private int attestationVersion;

	private KeyASecurityType attestationSecurityLevel;

	private int keymasterVersion;

	private KeyASecurityType keymasterSecurityLevel;

	private byte[] attestationChallenge;

	private String reserved;

	private AuthorizationList softwareEnforced;

	private AuthorizationList teeEnforced;

	public int getAttestationVersion() {
		return attestationVersion;
	}

	public void setAttestationVersion(int attestationVersion) {
		this.attestationVersion = attestationVersion;
	}

	public KeyASecurityType getAttestationSecurityLevel() {
		return attestationSecurityLevel;
	}

	public void setAttestationSecurityLevel(int attestationSecurityLevel) {
		this.attestationSecurityLevel = KeyASecurityType.convert(attestationSecurityLevel);
	}

	public int getKeymasterVersion() {
		return keymasterVersion;
	}

	public void setKeymasterVersion(int keymasterVersion) {
		this.keymasterVersion = keymasterVersion;
	}

	public KeyASecurityType getKeymasterSecurityLevel() {
		return keymasterSecurityLevel;
	}

	public void setKeymasterSecurityLevel(int keymasterSecurityLevel) {
		this.keymasterSecurityLevel = KeyASecurityType.convert(keymasterSecurityLevel);
	}

	public byte[] getAttestationChallenge() {
		return attestationChallenge;
	}

	public void setAttestationChallenge(byte[] attestationChallenge) {
		this.attestationChallenge = attestationChallenge;
	}

	public String getReserved() {
		return reserved;
	}

	public void setReserved(String reserved) {
		this.reserved = reserved;
	}

	public AuthorizationList getSoftwareEnforced() {
		return softwareEnforced;
	}

	public void setSoftwareEnforced(AuthorizationList softwareEnforced) {
		this.softwareEnforced = softwareEnforced;
	}

	public AuthorizationList getTeeEnforced() {
		return teeEnforced;
	}

	public void setTeeEnforced(AuthorizationList teeEnforced) {
		this.teeEnforced = teeEnforced;
	}
}
