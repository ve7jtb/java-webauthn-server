package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.databind.JsonNode;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.yubico.webauthn.data.ByteArray;
import java.io.IOException;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Parsed representation of {@code attStmt.mtcCert} (either proof-carrying {@code mtcEntryDesc} or
 * proof-less {@code mtcKeyRef}).
 */
@Value
@Builder(toBuilder = true)
public class MtcCertDescriptor {

  @NonNull private final ByteArray caId;
  private final long serial;
  private final Long notBefore;
  private final Long notAfter;
  private final Long fwVersion;
  private final ByteArray mtcProof;

  public Optional<Long> getNotBefore() {
    return Optional.ofNullable(notBefore);
  }

  public Optional<Long> getNotAfter() {
    return Optional.ofNullable(notAfter);
  }

  public Optional<Long> getFwVersion() {
    return Optional.ofNullable(fwVersion);
  }

  public Optional<Long> getFirmwareVersion() {
    return Optional.ofNullable(fwVersion);
  }

  public Optional<ByteArray> getMtcProof() {
    return Optional.ofNullable(mtcProof);
  }

  public int getLogNumber() {
    return (int) ((serial >>> 48) & 0xFFFFL);
  }

  public long getLeafIndex() {
    return serial & 0xFFFFFFFFFFFFL;
  }

  public static MtcCertDescriptor fromJsonNode(@NonNull JsonNode node) {
    if (!node.isObject()) {
      throw new IllegalArgumentException("mtcCert must be a CBOR/JSON map.");
    }
    JsonNode caIdNode = node.get("caId");
    if (caIdNode == null || (!caIdNode.isBinary() && !caIdNode.isTextual())) {
      throw new IllegalArgumentException("mtcCert.caId must be a byte string.");
    }
    final ByteArray caId;
    try {
      caId = new ByteArray(caIdNode.binaryValue());
    } catch (IOException e) {
      throw new IllegalArgumentException("Failed to decode mtcCert.caId.", e);
    }

    JsonNode serialNode = node.get("serial");
    if (serialNode == null || !serialNode.canConvertToLong()) {
      throw new IllegalArgumentException("mtcCert.serial must be an integer.");
    }
    long serial = serialNode.longValue();

    Long notBefore = readOptionalLong(node, "notBefore");
    Long notAfter = readOptionalLong(node, "notAfter");
    Long fwVersion = readOptionalLong(node, "firmwareVersion");
    if (fwVersion == null) {
      fwVersion = readOptionalLong(node, "fwVersion");
    }
    if (fwVersion != null && (fwVersion < 0 || fwVersion > 0xFFFFFFFFL)) {
      throw new IllegalArgumentException(
          "mtcCert.firmwareVersion must be a 32-bit unsigned integer (0..0xFFFFFFFF).");
    }

    ByteArray mtcProof = null;
    JsonNode proofNode = node.get("mtcProof");
    if (proofNode != null && !proofNode.isNull()) {
      if (!proofNode.isBinary() && !proofNode.isTextual()) {
        throw new IllegalArgumentException("mtcCert.mtcProof must be a byte string.");
      }
      try {
        mtcProof = new ByteArray(proofNode.binaryValue());
      } catch (IOException e) {
        throw new IllegalArgumentException("Failed to decode mtcCert.mtcProof.", e);
      }
    }

    if (mtcProof != null && (notBefore == null || notAfter == null)) {
      throw new IllegalArgumentException(
          "mtcCert with mtcProof (mtcEntryDesc) must include notBefore and notAfter.");
    }

    return MtcCertDescriptor.builder()
        .caId(caId)
        .serial(serial)
        .notBefore(notBefore)
        .notAfter(notAfter)
        .fwVersion(fwVersion)
        .mtcProof(mtcProof)
        .build();
  }

  public static MtcCertDescriptor fromCbor(@NonNull CBORObject cbor) {
    if (cbor.getType() != CBORType.Map) {
      throw new IllegalArgumentException("mtcCert must be a CBOR map.");
    }
    CBORObject caIdObj = cbor.get("caId");
    if (caIdObj == null || caIdObj.getType() != CBORType.ByteString) {
      throw new IllegalArgumentException("mtcCert.caId must be a CBOR byte string.");
    }
    ByteArray caId = new ByteArray(caIdObj.GetByteString());

    CBORObject serialObj = cbor.get("serial");
    if (serialObj == null || !serialObj.isNumber() || !serialObj.AsNumber().IsInteger()) {
      throw new IllegalArgumentException("mtcCert.serial must be a CBOR integer.");
    }
    long serial = serialObj.AsInt64Value();

    Long notBefore = readOptionalCborLong(cbor, "notBefore");
    Long notAfter = readOptionalCborLong(cbor, "notAfter");
    Long fwVersion = readOptionalCborLong(cbor, "firmwareVersion");
    if (fwVersion == null) {
      fwVersion = readOptionalCborLong(cbor, "fwVersion");
    }
    if (fwVersion != null && (fwVersion < 0 || fwVersion > 0xFFFFFFFFL)) {
      throw new IllegalArgumentException(
          "mtcCert.firmwareVersion must be a 32-bit unsigned integer (0..0xFFFFFFFF).");
    }

    ByteArray mtcProof = null;
    CBORObject proofObj = cbor.get("mtcProof");
    if (proofObj != null && !proofObj.isNull()) {
      if (proofObj.getType() != CBORType.ByteString) {
        throw new IllegalArgumentException("mtcCert.mtcProof must be a CBOR byte string.");
      }
      mtcProof = new ByteArray(proofObj.GetByteString());
    }

    if (mtcProof != null && (notBefore == null || notAfter == null)) {
      throw new IllegalArgumentException(
          "mtcCert with mtcProof (mtcEntryDesc) must include notBefore and notAfter.");
    }

    return MtcCertDescriptor.builder()
        .caId(caId)
        .serial(serial)
        .notBefore(notBefore)
        .notAfter(notAfter)
        .fwVersion(fwVersion)
        .mtcProof(mtcProof)
        .build();
  }

  private static Long readOptionalLong(JsonNode node, String field) {
    JsonNode child = node.get(field);
    if (child == null || child.isNull()) {
      return null;
    }
    if (!child.canConvertToLong()) {
      throw new IllegalArgumentException("mtcCert." + field + " must be an integer.");
    }
    return child.longValue();
  }

  private static Long readOptionalCborLong(CBORObject cbor, String field) {
    CBORObject child = cbor.get(field);
    if (child == null || child.isNull()) {
      return null;
    }
    if (!child.isNumber() || !child.AsNumber().IsInteger()) {
      throw new IllegalArgumentException("mtcCert." + field + " must be a CBOR integer.");
    }
    return child.AsInt64Value();
  }
}
