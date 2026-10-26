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
 * Represents a pre-verified or signed FIDO MTC subtree root hash entry from an {@link
 * MtcTrustAnchor}.
 */
@Value
@Builder(toBuilder = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MtcSubtree {

  private final Integer logNumber;
  private final long start;
  private final long end;
  @NonNull private final ByteArray rootHash;
  private final long alg;
  @NonNull private final ByteArray signature;
  private final ByteArray signingCert;

  public MtcSubtree(
      Integer logNumber,
      long start,
      long end,
      @NonNull ByteArray rootHash,
      long alg,
      @NonNull ByteArray signature,
      ByteArray signingCert) {
    this.logNumber = logNumber;
    this.start = start;
    this.end = end;
    this.rootHash = rootHash;
    this.alg = alg;
    this.signature = signature;
    this.signingCert = signingCert;
  }

  @JsonCreator
  public static MtcSubtree fromJson(JsonNode node) {
    if (node == null || !node.isObject()) {
      throw new IllegalArgumentException("Expected JSON object for MtcSubtree");
    }
    Integer logNumber = node.hasNonNull("logNumber") ? node.get("logNumber").asInt() : null;
    long start = node.path("start").asLong(0L);
    long end = node.path("end").asLong(0L);
    ByteArray rootHash = MtcTrustAnchor.parseFlexibleBytes(node.get("rootHash"), "rootHash");
    long alg =
        node.hasNonNull("alg")
            ? node.get("alg").asLong()
            : (node.hasNonNull("algorithm") ? node.get("algorithm").asLong() : 0L);
    ByteArray signature =
        node.hasNonNull("signature")
            ? MtcTrustAnchor.parseFlexibleBytes(node.get("signature"), "signature")
            : new ByteArray(new byte[0]);
    ByteArray signingCert =
        node.hasNonNull("signingCert")
            ? MtcTrustAnchor.parseFlexibleBytes(node.get("signingCert"), "signingCert")
            : null;
    return new MtcSubtree(logNumber, start, end, rootHash, alg, signature, signingCert);
  }

  public Optional<Integer> getLogNumber() {
    return Optional.ofNullable(logNumber);
  }

  public Optional<ByteArray> getSigningCert() {
    return Optional.ofNullable(signingCert);
  }
}
