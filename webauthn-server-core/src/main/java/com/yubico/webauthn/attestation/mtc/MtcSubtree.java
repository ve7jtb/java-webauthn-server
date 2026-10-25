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

  @JsonCreator
  public MtcSubtree(
      @JsonProperty("logNumber") Integer logNumber,
      @JsonProperty("start") long start,
      @JsonProperty("end") long end,
      @NonNull @JsonProperty("rootHash") ByteArray rootHash,
      @JsonProperty("alg") long alg,
      @NonNull @JsonProperty("signature") ByteArray signature,
      @JsonProperty("signingCert") ByteArray signingCert) {
    this.logNumber = logNumber;
    this.start = start;
    this.end = end;
    this.rootHash = rootHash;
    this.alg = alg;
    this.signature = signature;
    this.signingCert = signingCert;
  }

  public Optional<Integer> getLogNumber() {
    return Optional.ofNullable(logNumber);
  }

  public Optional<ByteArray> getSigningCert() {
    return Optional.ofNullable(signingCert);
  }
}
