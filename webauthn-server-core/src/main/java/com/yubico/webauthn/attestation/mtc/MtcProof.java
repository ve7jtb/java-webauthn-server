package com.yubico.webauthn.attestation.mtc;

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.ByteArray;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Decodes and represents the TLS-style wire format of {@code MTCProof} (per {@code
 * draft-ietf-plants-merkle-tree-certs}):
 *
 * <pre>
 * uint16 ext_len + opaque extensions[ext_len]
 * uint48 start
 * uint48 end
 * uint16 proof_bytes_len + HashValue inclusion_proof[proof_bytes_len / 32]
 * uint24 sig_len + opaque signatures[sig_len]
 * </pre>
 */
@Value
@Builder(toBuilder = true)
public class MtcProof {

  @NonNull private final ByteArray extensions;
  private final long start;
  private final long end;
  @NonNull private final List<ByteArray> inclusionProof;
  @NonNull private final ByteArray signatures;

  public static MtcProof parse(@NonNull ByteArray rawBytes) {
    byte[] raw = rawBytes.getBytes();
    if (raw.length < 2) {
      throw new IllegalArgumentException("MTCProof too short to read extensions length.");
    }
    int extLen = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
    int offset = 2;
    if (raw.length < offset + extLen + 12 + 2) {
      throw new IllegalArgumentException("MTCProof truncated in extensions or range header.");
    }
    ByteArray extensions = new ByteArray(Arrays.copyOfRange(raw, offset, offset + extLen));
    offset += extLen;

    long start = readUint48(raw, offset);
    offset += 6;
    long end = readUint48(raw, offset);
    offset += 6;

    int proofBytesLen = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
    offset += 2;
    if (proofBytesLen % 32 != 0 || raw.length < offset + proofBytesLen + 3) {
      throw new IllegalArgumentException(
          "MTCProof invalid inclusion proof length: " + proofBytesLen);
    }

    List<ByteArray> inclusionProof = new ArrayList<>(proofBytesLen / 32);
    for (int i = 0; i < proofBytesLen; i += 32) {
      inclusionProof.add(new ByteArray(Arrays.copyOfRange(raw, offset + i, offset + i + 32)));
    }
    offset += proofBytesLen;

    int sigLen =
        ((raw[offset] & 0xFF) << 16) | ((raw[offset + 1] & 0xFF) << 8) | (raw[offset + 2] & 0xFF);
    offset += 3;
    if (raw.length != offset + sigLen) {
      throw new IllegalArgumentException(
          String.format(
              "MTCProof length mismatch: expected %d bytes, got %d bytes.",
              offset + sigLen, raw.length));
    }
    ByteArray signatures = new ByteArray(Arrays.copyOfRange(raw, offset, offset + sigLen));

    return MtcProof.builder()
        .extensions(extensions)
        .start(start)
        .end(end)
        .inclusionProof(CollectionUtil.immutableList(inclusionProof))
        .signatures(signatures)
        .build();
  }

  private static long readUint48(byte[] buf, int offset) {
    long v = 0;
    for (int i = 0; i < 6; i++) {
      v = (v << 8) | (buf[offset + i] & 0xFFL);
    }
    return v;
  }
}
