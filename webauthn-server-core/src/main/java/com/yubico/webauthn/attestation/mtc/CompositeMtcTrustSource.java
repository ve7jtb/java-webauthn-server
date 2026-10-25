package com.yubico.webauthn.attestation.mtc;

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.ByteArray;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;

/**
 * Combines multiple {@link MtcTrustSource} instances in order, merging or returning the best
 * matching {@link MtcTrustAnchor}.
 *
 * <p>When an enterprise vendor manifest provides {@code batchKeys} for the same {@code caId} whose
 * {@code subtrees} are published in FIDO MDS3, this composite trust source merges the key table and
 * subtrees so both proof-carrying and proof-less enterprise attestations can be verified.
 */
public class CompositeMtcTrustSource implements MtcTrustSource {

  private final List<MtcTrustSource> delegates;

  public CompositeMtcTrustSource(@NonNull MtcTrustSource... delegates) {
    this(Arrays.asList(delegates));
  }

  public CompositeMtcTrustSource(@NonNull List<MtcTrustSource> delegates) {
    this.delegates = CollectionUtil.immutableList(delegates);
  }

  @Override
  public Optional<MtcTrustAnchor> findMtcTrustAnchor(
      ByteArray caId, Optional<ByteArray> aaguid) {
    MtcTrustAnchor merged = null;
    for (MtcTrustSource delegate : delegates) {
      Optional<MtcTrustAnchor> found = delegate.findMtcTrustAnchor(caId, aaguid);
      if (found.isPresent()) {
        if (merged == null) {
          merged = found.get();
        } else {
          merged = mergeAnchors(merged, found.get());
        }
      }
    }
    return Optional.ofNullable(merged);
  }

  private static MtcTrustAnchor mergeAnchors(MtcTrustAnchor primary, MtcTrustAnchor secondary) {
    return primary.toBuilder()
        .subtrees(
            !primary.getSubtrees().isEmpty() ? primary.getSubtrees() : secondary.getSubtrees())
        .batchKeys(
            !primary.getBatchKeys().isEmpty() ? primary.getBatchKeys() : secondary.getBatchKeys())
        .build();
  }
}
