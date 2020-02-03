package com.xin.attestation.utils;

import java.util.Arrays;

/**
 * Created by zhangchao on 1/9/18.
 */

public class AuthorizationList {

	public static final int KM_TAG_PURPOSE = 1;
	public static final int KM_TAG_ALGORITHM = 2;
	public static final int KM_TAG_KEY_SIZE = 3;
	public static final int KM_TAG_DIGEST = 5;
	public static final int KM_TAG_PADDING = 6;
	public static final int KM_TAG_ECCURVE = 10;
	public static final int KM_TAG_ACTIVE_DATE_TIME = 400;
	public static final int KM_TAG_ORIGINATION_EXPIRE_DATE_TIME = 401;
	public static final int KM_TAG_USAGE_EXPIRE_DATE_TIME = 402;
	public static final int KM_TAG_NO_AUTH_REQUIRED = 503;
	public static final int KM_TAG_USER_AUTH_TYPE = 504;
	public static final int KM_TAG_AUTH_TIMEOUT = 505;
	public static final int KM_ALLOW_WHILE_ON_BODY = 506;
	public static final int KM_TAG_ALL_APPLICATIONS = 600;
	public static final int KM_TAG_APPLICATION_ID = 601;
	public static final int KM_TAG_CREATION_DATE_TIME = 701;
	public static final int KM_TAG_ORIGIN = 702;
	public static final int KM_TAG_ROLLBACK_RESISTANT = 703;
	public static final int KM_TAG_ROOT_OF_TRUST = 704;
	public static final int KM_TAG_OS_VERSION = 705;
	public static final int KM_TAG_PATCH_LEVEL = 706;
	public static final int KM_TAG_ATTESTATION_CHALLENGE = 708;
	public static final int KM_TAG_ATTESTATION_APPLICATION_ID = 709;

	private int[] purpose;

	private int algorithm;

	private int keySize;

	private int[] digest;

	private int[] padding;

	private int ecCurve;

	private int rsaPublicExponent;

	private int activeDateTime;

	private int originationExpireDateTime;

	private int usageExpireDateTime;

	private boolean noAuthRequired;

	private int userAuthType;

	private int authTimeout;

	private boolean allowWhileOnBody;

	private boolean allApplications;

	private byte[] applicationId;

	private int creationDateTime;

	private int origin;

	private boolean rollbackResitant;

	private RootOfTrust rootOfTrust;

	private int osVersion;

	private int osPatchLevel;

	private int attestationChallenge;

	private byte[] attestationApplicationId;

	public int[] getPurpose() {
		return purpose;
	}

	public void setPurpose(int[] purpose) {
		this.purpose = purpose;
	}

	public int getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(int algorithm) {
		this.algorithm = algorithm;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	public int[] getDigest() {
		return digest;
	}

	public void setDigest(int[] digest) {
		this.digest = digest;
	}

	public int[] getPadding() {
		return padding;
	}

	public void setPadding(int[] padding) {
		this.padding = padding;
	}

	public int getEcCurve() {
		return ecCurve;
	}

	public void setEcCurve(int ecCurve) {
		this.ecCurve = ecCurve;
	}

	public int getRsaPublicExponent() {
		return rsaPublicExponent;
	}

	public void setRsaPublicExponent(int rsaPublicExponent) {
		this.rsaPublicExponent = rsaPublicExponent;
	}

	public int getActiveDateTime() {
		return activeDateTime;
	}

	public void setActiveDateTime(int activeDateTime) {
		this.activeDateTime = activeDateTime;
	}

	public int getOriginationExpireDateTime() {
		return originationExpireDateTime;
	}

	public void setOriginationExpireDateTime(int originationExpireDateTime) {
		this.originationExpireDateTime = originationExpireDateTime;
	}

	public int getUsageExpireDateTime() {
		return usageExpireDateTime;
	}

	public void setUsageExpireDateTime(int usageExpireDateTime) {
		this.usageExpireDateTime = usageExpireDateTime;
	}

	public boolean isNoAuthRequired() {
		return noAuthRequired;
	}

	public void setNoAuthRequired(boolean noAuthRequired) {
		this.noAuthRequired = noAuthRequired;
	}

	public int getUserAuthType() {
		return userAuthType;
	}

	public void setUserAuthType(int userAuthType) {
		this.userAuthType = userAuthType;
	}

	public int getAuthTimeout() {
		return authTimeout;
	}

	public void setAuthTimeout(int authTimeout) {
		this.authTimeout = authTimeout;
	}

	public boolean isAllowWhileOnBody() {
		return allowWhileOnBody;
	}

	public void setAllowWhileOnBody(boolean allowWhileOnBody) {
		this.allowWhileOnBody = allowWhileOnBody;
	}

	public boolean isAllApplications() {
		return allApplications;
	}

	public void setAllApplications(boolean allApplications) {
		this.allApplications = allApplications;
	}

	public byte[] getApplicationId() {
		return applicationId;
	}

	public void setApplicationId(byte[] applicationId) {
		this.applicationId = applicationId;
	}

	public int getCreationDateTime() {
		return creationDateTime;
	}

	public void setCreationDateTime(int creationDateTime) {
		this.creationDateTime = creationDateTime;
	}

	public int getOrigin() {
		return origin;
	}

	public void setOrigin(int origin) {
		this.origin = origin;
	}

	public boolean isRollbackResitant() {
		return rollbackResitant;
	}

	public void setRollbackResitant(boolean rollbackResitant) {
		this.rollbackResitant = rollbackResitant;
	}

	public RootOfTrust getRootOfTrust() {
		return rootOfTrust;
	}

	public void setRootOfTrust(RootOfTrust rootOfTrust) {
		this.rootOfTrust = rootOfTrust;
	}

	public int getOsVersion() {
		return osVersion;
	}

	public void setOsVersion(int osVersion) {
		this.osVersion = osVersion;
	}

	public int getOsPatchLevel() {
		return osPatchLevel;
	}

	public void setOsPatchLevel(int osPatchLevel) {
		this.osPatchLevel = osPatchLevel;
	}

	public int getAttestationChallenge() {
		return attestationChallenge;
	}

	public void setAttestationChallenge(int attestationChallenge) {
		this.attestationChallenge = attestationChallenge;
	}

	public byte[] getAttestationApplicationId() {
		return attestationApplicationId;
	}

	public void setAttestationApplicationId(byte[] attestationApplicationId) {
		this.attestationApplicationId = attestationApplicationId;
	}

	@Override
	public String toString() {
		return "AuthorizationList{" + "purpose=" + Arrays.toString(purpose) + ", algorithm=" + algorithm + ", keySize="
				+ keySize + ", digest=" + Arrays.toString(digest) + ", padding=" + Arrays.toString(padding)
				+ ", ecCurve=" + ecCurve + ", rsaPublicExponent=" + rsaPublicExponent + ", activeDateTime="
				+ activeDateTime + ", originationExpireDateTime=" + originationExpireDateTime + ", usageExpireDateTime="
				+ usageExpireDateTime + ", noAuthRequired=" + noAuthRequired + ", userAuthType=" + userAuthType
				+ ", authTimeout=" + authTimeout + ", allowWhileOnBody=" + allowWhileOnBody + ", allApplications="
				+ allApplications + ", applicationId='" + (applicationId != null ? new String(applicationId) : null)
				+ '\'' + ", creationDateTime=" + creationDateTime + ", origin=" + origin + ", rollbackResitant="
				+ rollbackResitant + ", rootOfTrust=" + rootOfTrust + ", osVersion=" + osVersion + ", osPatchLevel="
				+ osPatchLevel + ", attestationChallenge=" + attestationChallenge + ", attestationApplicationId="
				+ (attestationApplicationId != null ? new String(attestationApplicationId) : null) + '}';
	}
}
