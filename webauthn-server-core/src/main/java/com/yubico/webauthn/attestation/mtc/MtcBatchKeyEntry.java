package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;
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

  public MtcBatchKeyEntry(
      long serial,
      Long alg,
      @NonNull ByteArray coseKey,
      String deviceSerial,
      Long notBefore,
      Long notAfter,
      Long firmwareVersion) {
    this.serial = serial;
    this.alg = alg;
    this.coseKey = coseKey;
    this.deviceSerial = deviceSerial;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.firmwareVersion = firmwareVersion;
  }

  @JsonCreator
  public static MtcBatchKeyEntry fromJson(JsonNode node) {
    return fromJsonNode(node, null);
  }

  static MtcBatchKeyEntry fromJsonNode(JsonNode node, Long fallbackSerial) {
    if (node == null || !node.isObject()) {
      throw new IllegalArgumentException("Expected JSON object for MtcBatchKeyEntry");
    }
    long serial;
    if (node.hasNonNull("serial")) {
      JsonNode sNode = node.get("serial");
      serial = sNode.isNumber() ? sNode.asLong() : Long.decode(sNode.asText().trim());
    } else if (fallbackSerial != null) {
      serial = fallbackSerial;
    } else {
      throw new IllegalArgumentException("Missing serial in MtcBatchKeyEntry");
    }

    Long alg = null;
    if (node.hasNonNull("alg")) {
      alg = node.get("alg").asLong();
    } else if (node.hasNonNull("algorithm")) {
      alg = node.get("algorithm").asLong();
    }

    JsonNode keyNode = node.hasNonNull("coseKey") ? node.get("coseKey") : node.get("publicKey");
    ByteArray coseKey = MtcTrustAnchor.parseFlexibleBytes(keyNode, "coseKey");

    String deviceSerial =
        node.hasNonNull("deviceSerial") ? node.get("deviceSerial").asText() : null;
    Long notBefore = node.hasNonNull("notBefore") ? node.get("notBefore").asLong() : null;
    Long notAfter = node.hasNonNull("notAfter") ? node.get("notAfter").asLong() : null;
    Long firmwareVersion = null;
    if (node.hasNonNull("firmwareVersion")) {
      firmwareVersion = node.get("firmwareVersion").asLong();
    } else if (node.hasNonNull("fwVersion")) {
      firmwareVersion = node.get("fwVersion").asLong();
    }

    return new MtcBatchKeyEntry(
        serial, alg, coseKey, deviceSerial, notBefore, notAfter, firmwareVersion);
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
