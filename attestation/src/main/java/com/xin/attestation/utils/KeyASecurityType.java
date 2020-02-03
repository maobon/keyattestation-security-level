package com.xin.attestation.utils;

/**
 * Created by zhangchao on 1/9/18.
 */

public enum KeyASecurityType {
	SOFTWARE, TEE, NOATTESTATION;

	public static KeyASecurityType convert(int i) {
		if (i == 0) {
			return SOFTWARE;
		}
		if (i == 1) {
			return TEE;
		}
		return NOATTESTATION;
	}
}
