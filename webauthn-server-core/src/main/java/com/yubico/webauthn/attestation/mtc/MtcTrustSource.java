package com.yubico.webauthn.attestation.mtc;

import com.yubico.webauthn.data.ByteArray;
import java.util.Optional;

/**
 * Abstraction for looking up Merkle Tree Certificate ({@code fmt: "mtc"}) trust anchors by {@code
 * caId} and optional {@code aaguid}.
 */
public interface MtcTrustSource {

  /**
   * Attempt to find a trusted {@link MtcTrustAnchor} for the given {@code caId} and optional
   * authenticator {@code aaguid}.
   *
   * @param caId the MTC CA identifier from {@code attStmt.mtcCert.caId}.
   * @param aaguid the authenticator's 16-byte AAGUID from {@code attestedCredentialData}, if
   *     present.
   * @return the matching {@link MtcTrustAnchor}, if found.
   */
  Optional<MtcTrustAnchor> findMtcTrustAnchor(ByteArray caId, Optional<ByteArray> aaguid);

  /** Returns an empty {@link MtcTrustSource} that matches no trust anchors. */
  static MtcTrustSource empty() {
    return (caId, aaguid) -> Optional.empty();
  }
}
