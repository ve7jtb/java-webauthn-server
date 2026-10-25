package com.yubico.webauthn.attestation.mtc;

import com.yubico.webauthn.Crypto;
import com.yubico.webauthn.data.ByteArray;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * Evaluates RFC 9162 §2.1.3.2 Merkle inclusion proofs for a subtree {@code [start, end)}.
 */
@UtilityClass
public class MerkleInclusion {

  /**
   * Evaluates a Merkle inclusion proof for leaf {@code index} within subtree {@code [start, end)}
   * starting from {@code leafHash}.
   *
   * @return the reconstructed 32-byte subtree root hash, or {@link Optional#empty()} if the parameters or
   *     proof path length are invalid.
   */
  public static Optional<ByteArray> evaluateInclusionProof(
      long index,
      long start,
      long end,
      @NonNull ByteArray leafHash,
      @NonNull List<ByteArray> inclusionProof) {
    if (leafHash.getBytes().length != 32) {
      return Optional.empty();
    }
    if (end <= start || index < start || index >= end) {
      return Optional.empty();
    }
    long n = end - start;
    if (n == 1) {
      return inclusionProof.isEmpty() ? Optional.of(leafHash) : Optional.empty();
    }

    long fnIdx = index - start;
    long sn = n - 1;
    byte[] r = leafHash.getBytes().clone();

    for (ByteArray pElem : inclusionProof) {
      byte[] p = pElem.getBytes();
      if (p.length != 32 || sn == 0) {
        return Optional.empty();
      }
      if ((fnIdx & 1L) == 1L || fnIdx == sn) {
        r = hashInteriorNode(p, r);
        while ((fnIdx & 1L) == 0L && fnIdx != 0L) {
          fnIdx >>>= 1;
          sn >>>= 1;
        }
      } else {
        r = hashInteriorNode(r, p);
      }
      fnIdx >>>= 1;
      sn >>>= 1;
    }

    if (sn != 0L) {
      return Optional.empty();
    }
    return Optional.of(new ByteArray(r));
  }

  private static byte[] hashInteriorNode(byte[] left, byte[] right) {
    byte[] combined = new byte[1 + 32 + 32];
    combined[0] = 0x01;
    System.arraycopy(left, 0, combined, 1, 32);
    System.arraycopy(right, 0, combined, 33, 32);
    return Crypto.sha256(new ByteArray(combined)).getBytes();
  }
}
