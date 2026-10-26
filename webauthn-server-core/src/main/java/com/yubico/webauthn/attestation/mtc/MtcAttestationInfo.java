package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Summary of a verified Merkle Tree Certificate ({@code fmt: "mtc"}) attestation statement,
 * attached to {@link com.yubico.webauthn.RegistrationResult}.
 */
@Value
@Builder(toBuilder = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MtcAttestationInfo {

  /** How the attestation public key (and optional enterprise device serial) was resolved. */
  public enum KeySource {
    /** Batch attestation key resolved from FIDO MDS3 {@code MtcTrustAnchor.batchKeys}. */
    MDS_BATCH_KEY_TABLE,
    /** Enterprise attestation key resolved from an enterprise vendor key manifest. */
    ENTERPRISE_MANIFEST,
    /**
     * Attestation key (and optional enterprise {@code deviceSerial}) resolved from the {@code
     * mtc-debug} authenticator extension and cryptographically verified against an MDS subtree
     * root hash via {@code mtcProof}.
     */
    MTC_DEBUG_EXTENSION
  }

  @NonNull private final ByteArray caId;
  private final long serial;
  private final int logNumber;
  private final long leafIndex;
  private final Long notBefore;
  private final Long notAfter;

  @JsonProperty("firmwareVersion")
  @JsonAlias("fwVersion")
  private final Long fwVersion;

  private final ByteArray subtreeRootHash;
  private final ByteArray leafHash;
  private final String deviceSerial;
  private final boolean enterprise;
  private final boolean proofVerified;
  @NonNull private final KeySource keySource;

  @JsonCreator
  public MtcAttestationInfo(
      @NonNull @JsonProperty("caId") ByteArray caId,
      @JsonProperty("serial") long serial,
      @JsonProperty("logNumber") int logNumber,
      @JsonProperty("leafIndex") long leafIndex,
      @JsonProperty("notBefore") Long notBefore,
      @JsonProperty("notAfter") Long notAfter,
      @JsonProperty("firmwareVersion") @JsonAlias("fwVersion") Long fwVersion,
      @JsonProperty("subtreeRootHash") ByteArray subtreeRootHash,
      @JsonProperty("leafHash") ByteArray leafHash,
      @JsonProperty("deviceSerial") String deviceSerial,
      @JsonProperty("enterprise") boolean enterprise,
      @JsonProperty("proofVerified") boolean proofVerified,
      @NonNull @JsonProperty("keySource") KeySource keySource) {
    this.caId = caId;
    this.serial = serial;
    this.logNumber = logNumber;
    this.leafIndex = leafIndex;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.fwVersion = fwVersion;
    this.subtreeRootHash = subtreeRootHash;
    this.leafHash = leafHash;
    this.deviceSerial = deviceSerial;
    this.enterprise = enterprise;
    this.proofVerified = proofVerified;
    this.keySource = keySource;
  }

  public Optional<Long> getNotBefore() {
    return Optional.ofNullable(notBefore);
  }

  public Optional<Long> getNotAfter() {
    return Optional.ofNullable(notAfter);
  }

  @JsonIgnore
  public Optional<Long> getFwVersion() {
    return Optional.ofNullable(fwVersion);
  }

  @JsonProperty("firmwareVersion")
  public Optional<Long> getFirmwareVersion() {
    return Optional.ofNullable(fwVersion);
  }

  public Optional<ByteArray> getSubtreeRootHash() {
    return Optional.ofNullable(subtreeRootHash);
  }

  public Optional<ByteArray> getLeafHash() {
    return Optional.ofNullable(leafHash);
  }

  public Optional<String> getDeviceSerial() {
    return Optional.ofNullable(deviceSerial);
  }
}
