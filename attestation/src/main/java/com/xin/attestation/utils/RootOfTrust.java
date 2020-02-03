package com.xin.attestation.utils;

/**
 * Created by zhangchao on 1/9/18.
 */

public class RootOfTrust {

	public static final int VERIFIED_BOOT_KEY_INDEX = 0;
	public static final int DEVICE_LOCKED_INDEX = 1;
	public static final int VERIFIED_BOOT_STATE_INDEX = 2;

	private byte[] verifiedBootKey;

	private boolean DeviceLocked;

	private int verifiedBootState;

	public byte[] getVerifiedBootKey() {
		return verifiedBootKey;
	}

	public void setVerifiedBootKey(byte[] verifiedBootKey) {
		this.verifiedBootKey = verifiedBootKey;
	}

	public boolean isDeviceLocked() {
		return DeviceLocked;
	}

	public void setDeviceLocked(boolean deviceLocked) {
		DeviceLocked = deviceLocked;
	}

	public int getVerifiedBootState() {
		return verifiedBootState;
	}

	public void setVerifiedBootState(int verifiedBootState) {
		this.verifiedBootState = verifiedBootState;
	}

	@Override
	public String toString() {
		return "RootOfTrust{" + "verifiedBootKey='" + verifiedBootKey + '\'' + ", DeviceLocked=" + DeviceLocked
				+ ", verifiedBootState=" + verifiedBootState + '}';
	}
}
