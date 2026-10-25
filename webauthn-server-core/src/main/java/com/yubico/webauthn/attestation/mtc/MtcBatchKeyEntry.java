package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Represents an attestation public key entry in an {@link MtcTrustAnchor#getBatchKeys()
 * MtcTrustAnchor} key table (from FIDO MDS3 for batch attestation, or from an enterprise vendor
 * manifest for enterprise attestation).
 */
@Value
@Builder(toBuilder = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MtcBatchKeyEntry {

  private final long serial;
  private final Long alg;
  @NonNull private final ByteArray coseKey;
  private final String deviceSerial;
  private final Long notBefore;
  private final Long notAfter;
  private final Long firmwareVersion;

  public MtcBatchKeyEntry(
      long serial, Long alg, @NonNull ByteArray coseKey, String deviceSerial) {
    this(serial, alg, coseKey, deviceSerial, null, null, null);
  }

  @JsonCreator
  public MtcBatchKeyEntry(
      @JsonProperty("serial") long serial,
      @JsonProperty("alg") Long alg,
      @NonNull @JsonProperty("coseKey") ByteArray coseKey,
      @JsonProperty("deviceSerial") String deviceSerial,
      @JsonProperty("notBefore") Long notBefore,
      @JsonProperty("notAfter") Long notAfter,
      @JsonProperty("firmwareVersion") Long firmwareVersion) {
    this.serial = serial;
    this.alg = alg;
    this.coseKey = coseKey;
    this.deviceSerial = deviceSerial;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.firmwareVersion = firmwareVersion;
  }

  public Optional<Long> getAlg() {
    return Optional.ofNullable(alg);
  }

  public Optional<String> getDeviceSerial() {
    return Optional.ofNullable(deviceSerial);
  }

  public Optional<Long> getNotBefore() {
    return Optional.ofNullable(notBefore);
  }

  public Optional<Long> getNotAfter() {
    return Optional.ofNullable(notAfter);
  }

  public Optional<Long> getFirmwareVersion() {
    return Optional.ofNullable(firmwareVersion);
  }
}
