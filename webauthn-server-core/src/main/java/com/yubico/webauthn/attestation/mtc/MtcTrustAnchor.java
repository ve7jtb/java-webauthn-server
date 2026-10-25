package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.ByteArray;
import java.util.Collections;
import java.util.HashMap;
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
  @JsonCreator
  public MtcTrustAnchor(
      @NonNull @JsonProperty("caId") ByteArray caId,
      @JsonProperty("logNumber") Integer logNumber,
      @JsonProperty("hashAlg") String hashAlg,
      @JsonProperty("maxBatchWindow") Long maxBatchWindow,
      @JsonProperty("subtrees") List<MtcSubtree> subtrees,
      @JsonProperty("revokedSerials") Set<Long> revokedSerials,
      @JsonProperty("batchKeys") List<MtcBatchKeyEntry> batchKeys,
      @JsonProperty("aaguid") ByteArray aaguid,
      @JsonProperty("keyTableAuthenticated") Boolean keyTableAuthenticated) {
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
