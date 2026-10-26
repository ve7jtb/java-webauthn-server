package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.ByteArray;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Represents a Merkle Tree Certificate (MTC) trust anchor from FIDO MDS3 {@code
 * MetadataStatement.mtcTrustAnchors} or an enterprise vendor key manifest.
 */
@Value
@JsonIgnoreProperties(ignoreUnknown = true)
public class MtcTrustAnchor {

  @NonNull private final ByteArray caId;
  private final Integer logNumber;
  @NonNull private final String hashAlg;
  private final Long maxBatchWindow;
  @NonNull private final List<MtcSubtree> subtrees;
  @NonNull private final Set<Long> revokedSerials;
  @NonNull private final List<MtcBatchKeyEntry> batchKeys;
  private final ByteArray aaguid;

  /**
   * True if this trust anchor was loaded from an authenticated FIDO MDS3 BLOB or an authenticated
   * enterprise vendor manifest, allowing proof-less {@code mtcKeyRef} verification.
   */
  private final boolean keyTableAuthenticated;

  @JsonIgnore private final Map<Long, MtcBatchKeyEntry> batchKeysBySerial;

  @Builder(toBuilder = true)
  public MtcTrustAnchor(
      @NonNull ByteArray caId,
      Integer logNumber,
      String hashAlg,
      Long maxBatchWindow,
      List<MtcSubtree> subtrees,
      Set<Long> revokedSerials,
      List<MtcBatchKeyEntry> batchKeys,
      ByteArray aaguid,
      Boolean keyTableAuthenticated) {
    this.caId = caId;
    this.logNumber = logNumber;
    this.hashAlg = hashAlg == null ? "sha-256" : hashAlg;
    this.maxBatchWindow = maxBatchWindow;
    this.subtrees =
        subtrees == null ? Collections.emptyList() : CollectionUtil.immutableList(subtrees);
    this.revokedSerials =
        revokedSerials == null
            ? Collections.emptySet()
            : CollectionUtil.immutableSet(revokedSerials);
    this.batchKeys =
        batchKeys == null ? Collections.emptyList() : CollectionUtil.immutableList(batchKeys);
    this.aaguid = aaguid;
    this.keyTableAuthenticated = keyTableAuthenticated == null || keyTableAuthenticated;

    Map<Long, MtcBatchKeyEntry> bySerial = new HashMap<>();
    for (MtcBatchKeyEntry entry : this.batchKeys) {
      bySerial.put(entry.getSerial(), entry);
    }
    this.batchKeysBySerial = Collections.unmodifiableMap(bySerial);
  }

  static ByteArray parseFlexibleBytes(JsonNode node, String fieldName) {
    if (node == null || node.isNull() || !node.isTextual()) {
      throw new IllegalArgumentException("Missing or non-textual ByteArray field: " + fieldName);
    }
    String raw = node.asText().trim();
    if (raw.contains("+") || raw.contains("/")) {
      return ByteArray.fromBase64(raw);
    }
    try {
      return ByteArray.fromBase64Url(raw);
    } catch (Exception e) {
      try {
        return ByteArray.fromBase64(raw);
      } catch (Exception e2) {
        try {
          return ByteArray.fromHex(raw.replace("-", ""));
        } catch (Exception e3) {
          throw new IllegalArgumentException(
              "Invalid encoding for field " + fieldName + ": " + raw, e);
        }
      }
    }
  }

  static ByteArray parseOptionalAaguid(JsonNode node) {
    if (node == null || node.isNull() || !node.isTextual()) {
      return null;
    }
    String raw = node.asText().trim();
    String hex = raw.replace("-", "");
    if (hex.length() == 32 && hex.matches("[0-9a-fA-F]+")) {
      try {
        return ByteArray.fromHex(hex);
      } catch (Exception ignored) {
      }
    }
    return parseFlexibleBytes(node, "aaguid");
  }

  @JsonCreator
  public static MtcTrustAnchor fromJson(JsonNode node) {
    if (node == null || !node.isObject()) {
      throw new IllegalArgumentException("Expected JSON object for MtcTrustAnchor");
    }
    ByteArray caId = parseFlexibleBytes(node.get("caId"), "caId");
    Integer logNumber = node.hasNonNull("logNumber") ? node.get("logNumber").asInt() : null;
    String hashAlg = node.hasNonNull("hashAlg") ? node.get("hashAlg").asText() : "sha-256";
    Long maxBatchWindow =
        node.hasNonNull("maxBatchWindow") ? node.get("maxBatchWindow").asLong() : null;

    List<MtcSubtree> subtrees = new ArrayList<>();
    JsonNode subtreesNode =
        node.has("subtrees") ? node.get("subtrees") : node.get("trustedSubtrees");
    if (subtreesNode != null && subtreesNode.isArray()) {
      for (JsonNode stNode : subtreesNode) {
        subtrees.add(MtcSubtree.fromJson(stNode));
      }
    }

    Set<Long> revokedSerials = new HashSet<>();
    JsonNode revokedNode = node.get("revokedSerials");
    if (revokedNode != null && revokedNode.isArray()) {
      for (JsonNode rNode : revokedNode) {
        if (rNode.isNumber()) {
          revokedSerials.add(rNode.asLong());
        } else if (rNode.isTextual()) {
          revokedSerials.add(Long.decode(rNode.asText().trim()));
        }
      }
    }

    List<MtcBatchKeyEntry> batchKeys = new ArrayList<>();
    JsonNode bkNode = node.get("batchKeys");
    if (bkNode != null) {
      if (bkNode.isArray()) {
        for (JsonNode item : bkNode) {
          batchKeys.add(MtcBatchKeyEntry.fromJsonNode(item, null));
        }
      } else if (bkNode.isObject()) {
        if (bkNode.has("coseKey") || bkNode.has("publicKey")) {
          batchKeys.add(MtcBatchKeyEntry.fromJsonNode(bkNode, null));
        } else {
          Iterator<Map.Entry<String, JsonNode>> fields = bkNode.fields();
          while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            Long fallbackSerial = Long.decode(entry.getKey().trim());
            batchKeys.add(MtcBatchKeyEntry.fromJsonNode(entry.getValue(), fallbackSerial));
          }
        }
      }
    }

    ByteArray aaguid = parseOptionalAaguid(node.get("aaguid"));
    Boolean keyTableAuthenticated =
        node.hasNonNull("keyTableAuthenticated")
            ? node.get("keyTableAuthenticated").asBoolean()
            : Boolean.TRUE;

    return new MtcTrustAnchor(
        caId,
        logNumber,
        hashAlg,
        maxBatchWindow,
        subtrees,
        revokedSerials,
        batchKeys,
        aaguid,
        keyTableAuthenticated);
  }

  public Optional<Integer> getLogNumber() {
    return Optional.ofNullable(logNumber);
  }

  public Optional<Long> getMaxBatchWindow() {
    return Optional.ofNullable(maxBatchWindow);
  }

  public Optional<ByteArray> getAaguid() {
    return Optional.ofNullable(aaguid);
  }

  public Optional<MtcBatchKeyEntry> findBatchKey(long serial) {
    return Optional.ofNullable(batchKeysBySerial.get(serial));
  }
}
