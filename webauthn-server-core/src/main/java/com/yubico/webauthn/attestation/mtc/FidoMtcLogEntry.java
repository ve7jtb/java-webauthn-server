package com.yubico.webauthn.attestation.mtc;

import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.Crypto;
import com.yubico.webauthn.data.ByteArray;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Deterministic binary log entry structure ({@code FidoMtcLogEntry}) and RFC 9162 domain-separated
 * leaf hash computation ({@code SHA-256(0x00 || entryBytes)}).
 */
@Value
@Builder(toBuilder = true)
public class FidoMtcLogEntry {

  @NonNull private final ByteArray caId;
  private final long serial;
  private final long notBefore;
  private final long notAfter;
  @NonNull private final ByteArray aaguid;
  @NonNull @Builder.Default private final Optional<Long> fwVersion = Optional.empty();
  @NonNull private final ByteArray pubKeyHash;
  @NonNull @Builder.Default private final ByteArray extensions = new ByteArray(new byte[0]);

  /**
   * Computes the 32-byte SHA-256 hash of a COSE_Key after canonical CBOR re-encoding (RFC 8949
   * §4.2.1).
   */
  public static ByteArray computeCanonicalCoseKeyHash(@NonNull ByteArray cosePublicKey) {
    CBORObject cborKey = CBORObject.DecodeFromBytes(cosePublicKey.getBytes());
    byte[] canonicalBytes = cborKey.EncodeToBytes();
    return Crypto.sha256(new ByteArray(canonicalBytes));
  }

  /** Serializes this {@code FidoMtcLogEntry} into its canonical byte representation. */
  public ByteArray toBytes() {
    byte[] caIdBytes = caId.getBytes();
    byte[] aaguidBytes = aaguid.getBytes();
    byte[] pubKeyHashBytes = pubKeyHash.getBytes();
    byte[] extBytes = extensions.getBytes();

    if (aaguidBytes.length != 16) {
      throw new IllegalArgumentException(
          "FidoMtcLogEntry aaguid must be 16 bytes, was: " + aaguidBytes.length);
    }
    if (pubKeyHashBytes.length != 32) {
      throw new IllegalArgumentException(
          "FidoMtcLogEntry pubKeyHash must be 32 bytes, was: " + pubKeyHashBytes.length);
    }

    int fwLen = fwVersion.isPresent() ? 9 : 1;
    int totalLen = 2 + caIdBytes.length + 8 + 8 + 8 + 16 + fwLen + 32 + 2 + extBytes.length;

    ByteBuffer buf = ByteBuffer.allocate(totalLen);
    buf.putShort((short) caIdBytes.length);
    buf.put(caIdBytes);
    buf.putLong(serial);
    buf.putLong(notBefore);
    buf.putLong(notAfter);
    buf.put(aaguidBytes);
    if (fwVersion.isPresent()) {
      buf.put((byte) 0x01);
      buf.putLong(fwVersion.get());
    } else {
      buf.put((byte) 0x00);
    }
    buf.put(pubKeyHashBytes);
    buf.putShort((short) extBytes.length);
    buf.put(extBytes);

    return new ByteArray(buf.array());
  }

  /**
   * Computes the RFC 9162 §2.1.1 leaf hash: {@code SHA-256(0x00 || toBytes())}.
   */
  public ByteArray computeLeafHash() {
    byte[] entryBytes = toBytes().getBytes();
    ByteArrayOutputStream out = new ByteArrayOutputStream(1 + entryBytes.length);
    out.write(0x00);
    out.write(entryBytes, 0, entryBytes.length);
    return Crypto.sha256(new ByteArray(out.toByteArray()));
  }
}
