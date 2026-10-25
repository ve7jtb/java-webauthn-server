package com.yubico.webauthn.attestation.mtc;

import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.Crypto;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Constructs and verifies {@code FidoMtcSubtreeCheckpoint} messages against FIDO MDS3 {@code
 * attestationRootCertificates}, including built-in RFC 8554 / RFC 8778 HSS-LMS ({@code alg: -46})
 * verification.
 */
@Slf4j
@UtilityClass
public class MtcCheckpoint {

  public static final long COSE_ALG_HSS_LMS = -46L;

  private static final byte[] CHECKPOINT_CONTEXT =
      "FIDO-MTC-SUBTREE-CHECKPOINT-V1\0\0".getBytes(StandardCharsets.US_ASCII);

  private static final byte[] D_PBLC = new byte[] {(byte) 0x80, (byte) 0x80};
  private static final byte[] D_MESG = new byte[] {(byte) 0x81, (byte) 0x81};
  private static final byte[] D_LEAF = new byte[] {(byte) 0x82, (byte) 0x82};
  private static final byte[] D_INTR = new byte[] {(byte) 0x83, (byte) 0x83};

  /** OID id-alg-hss-lms-hashsig = 1.2.840.113549.1.9.16.3.17 */
  private static final byte[] OID_HSS_LMS_DER =
      new byte[] {
        0x06, 0x0b, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x09, 0x10,
        0x03, 0x11
      };

  /**
   * Builds the deterministic {@code FidoMtcSubtreeCheckpoint} byte array (85 bytes when {@code
   * caId} is 5 bytes).
   */
  public static ByteArray buildCheckpointBytes(
      @NonNull ByteArray caId, int logNumber, long start, long end, @NonNull ByteArray rootHash) {
    byte[] caIdBytes = caId.getBytes();
    byte[] rootHashBytes = rootHash.getBytes();
    if (rootHashBytes.length != 32) {
      throw new IllegalArgumentException(
          "Subtree rootHash must be 32 bytes, was: " + rootHashBytes.length);
    }
    int totalLen = 32 + 2 + caIdBytes.length + 2 + 6 + 6 + 32;
    ByteBuffer buf = ByteBuffer.allocate(totalLen);
    buf.put(CHECKPOINT_CONTEXT);
    buf.putShort((short) caIdBytes.length);
    buf.put(caIdBytes);
    buf.putShort((short) (logNumber & 0xFFFF));
    putUint48(buf, start);
    putUint48(buf, end);
    buf.put(rootHashBytes);
    return new ByteArray(buf.array());
  }

  /**
   * Verifies an {@link MtcSubtree} checkpoint signature against the provided set of trusted X.509
   * certificates.
   */
  public static boolean verifySubtreeCheckpoint(
      @NonNull ByteArray caId,
      int defaultLogNumber,
      @NonNull MtcSubtree subtree,
      @NonNull Collection<X509Certificate> trustCertificates) {
    int logNumber = subtree.getLogNumber().orElse(defaultLogNumber);
    ByteArray checkpoint =
        buildCheckpointBytes(
            caId, logNumber, subtree.getStart(), subtree.getEnd(), subtree.getRootHash());

    if (subtree.getSigningCert().isPresent()) {
      try {
        X509Certificate leafCert =
            CertificateParser.parseDer(subtree.getSigningCert().get().getBytes());
        if (isCertTrustedOrSignedBy(leafCert, trustCertificates)
            && verifyWithCertificate(
                leafCert, checkpoint, subtree.getSignature(), subtree.getAlg())) {
          return true;
        }
      } catch (Exception e) {
        log.debug("Failed to verify subtree signingCert", e);
      }
    }

    for (X509Certificate cert : trustCertificates) {
      if (verifyWithCertificate(cert, checkpoint, subtree.getSignature(), subtree.getAlg())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Finds the first certificate in {@code trustCertificates} (or {@code subtree.getSigningCert()})
   * that verifies the {@link MtcSubtree} checkpoint signature.
   */
  public static Optional<X509Certificate> findSubtreeSigningCert(
      @NonNull ByteArray caId,
      int defaultLogNumber,
      @NonNull MtcSubtree subtree,
      @NonNull Collection<X509Certificate> trustCertificates) {
    int logNumber = subtree.getLogNumber().orElse(defaultLogNumber);
    ByteArray checkpoint =
        buildCheckpointBytes(
            caId, logNumber, subtree.getStart(), subtree.getEnd(), subtree.getRootHash());

    if (subtree.getSigningCert().isPresent()) {
      try {
        X509Certificate leafCert =
            CertificateParser.parseDer(subtree.getSigningCert().get().getBytes());
        if (isCertTrustedOrSignedBy(leafCert, trustCertificates)
            && verifyWithCertificate(
                leafCert, checkpoint, subtree.getSignature(), subtree.getAlg())) {
          return Optional.of(leafCert);
        }
      } catch (Exception e) {
        log.debug("Failed to verify subtree signingCert", e);
      }
    }

    for (X509Certificate cert : trustCertificates) {
      if (verifyWithCertificate(cert, checkpoint, subtree.getSignature(), subtree.getAlg())) {
        return Optional.of(cert);
      }
    }
    return Optional.empty();
  }

  private static boolean isCertTrustedOrSignedBy(
      X509Certificate target, Collection<X509Certificate> trustCertificates) {
    for (X509Certificate trusted : trustCertificates) {
      try {
        if (Arrays.equals(target.getEncoded(), trusted.getEncoded())) {
          return true;
        }
        Optional<byte[]> hssPub = extractHssLmsPublicKey(trusted);
        if (hssPub.isPresent()) {
          if (verifyHssLmsSignature(
              hssPub.get(), target.getTBSCertificate(), target.getSignature())) {
            return true;
          }
        } else {
          target.verify(trusted.getPublicKey());
          return true;
        }
      } catch (Exception ignored) {
      }
    }
    return false;
  }

  public static boolean verifyWithCertificate(
      @NonNull X509Certificate cert,
      @NonNull ByteArray message,
      @NonNull ByteArray signature,
      long coseAlg) {
    if (coseAlg == COSE_ALG_HSS_LMS) {
      Optional<byte[]> hssPub = extractHssLmsPublicKey(cert);
      return hssPub
          .map(pub -> verifyHssLmsSignature(pub, message.getBytes(), signature.getBytes()))
          .orElse(false);
    }

    Optional<COSEAlgorithmIdentifier> algOpt = COSEAlgorithmIdentifier.fromId(coseAlg);
    if (!algOpt.isPresent()) {
      return false;
    }
    try {
      return Crypto.verifySignature(cert, message, signature, algOpt.get());
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Extracts the 60-byte RFC 8554 L=1 HSS-LMS public key from an X.509 certificate's
   * SubjectPublicKeyInfo if its algorithm OID is {@code id-alg-hss-lms-hashsig} ({@code
   * 1.2.840.113549.1.9.16.3.17}).
   */
  public static Optional<byte[]> extractHssLmsPublicKey(@NonNull X509Certificate cert) {
    try {
      byte[] spki = cert.getPublicKey().getEncoded();
      if (spki == null || spki.length < 60 + OID_HSS_LMS_DER.length) {
        return Optional.empty();
      }
      if (!containsSubsequence(spki, OID_HSS_LMS_DER)) {
        return Optional.empty();
      }
      byte[] pub60 = Arrays.copyOfRange(spki, spki.length - 60, spki.length);
      return Optional.of(pub60);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /**
   * Verifies an RFC 8554 §§5.4.2, 6.3 L=1 HSS-LMS signature against a 60-byte HSS public key.
   */
  public static boolean verifyHssLmsSignature(
      @NonNull byte[] hssPubKey, @NonNull byte[] message, @NonNull byte[] hssSig) {
    try {
      byte[] pub = hssPubKey;
      if (pub.length == 62 && pub[0] == 0x04 && pub[1] == 0x3c) {
        pub = Arrays.copyOfRange(pub, 2, 62);
      }
      if (pub.length != 60) {
        return false;
      }

      ByteBuffer pubBuf = ByteBuffer.wrap(pub);
      int levels = pubBuf.getInt();
      int pubLmsType = pubBuf.getInt();
      int pubLmotsType = pubBuf.getInt();
      if (levels != 1) {
        return false;
      }

      int h = getLmsHeight(pubLmsType);
      int[] lmotsParams = getLmotsParams(pubLmotsType);
      if (h < 0 || lmotsParams == null) {
        return false;
      }
      int n = lmotsParams[0];
      int w = lmotsParams[1];
      int p = lmotsParams[2];
      int ls = lmotsParams[3];

      byte[] treeId = Arrays.copyOfRange(pub, 12, 28);
      byte[] rootHash = Arrays.copyOfRange(pub, 28, 60);

      int otsSigLen = 4 + n + p * n;
      int expectedSigLen = 4 + 4 + otsSigLen + 4 + h * 32;
      if (hssSig.length != expectedSigLen) {
        return false;
      }

      ByteBuffer sigBuf = ByteBuffer.wrap(hssSig);
      int nspk = sigBuf.getInt();
      int q = sigBuf.getInt();
      if (nspk != 0 || q < 0 || q >= (1 << h)) {
        return false;
      }

      int sigLmotsType = sigBuf.getInt();
      if (sigLmotsType != pubLmotsType) {
        return false;
      }

      byte[] cRand = new byte[n];
      sigBuf.get(cRand);

      byte[] iqPrefix = new byte[20];
      System.arraycopy(treeId, 0, iqPrefix, 0, 16);
      putInt32(iqPrefix, 16, q);

      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(iqPrefix);
      sha256.update(D_MESG);
      sha256.update(cRand);
      sha256.update(message);
      byte[] qHash = sha256.digest();

      int checksum = cksm(qHash, w, n, ls);
      byte[] qWithCksm = new byte[n + 2];
      System.arraycopy(qHash, 0, qWithCksm, 0, n);
      qWithCksm[n] = (byte) ((checksum >>> 8) & 0xFF);
      qWithCksm[n + 1] = (byte) (checksum & 0xFF);

      int maxDigit = (1 << w) - 1;
      MessageDigest kcDigest = MessageDigest.getInstance("SHA-256");
      kcDigest.update(iqPrefix);
      kcDigest.update(D_PBLC);

      byte[] chainStepInput = new byte[20 + 2 + 1 + n];
      System.arraycopy(iqPrefix, 0, chainStepInput, 0, 20);

      for (int i = 0; i < p; i++) {
        int a = coef(qWithCksm, i, w);
        byte[] tmp = new byte[n];
        sigBuf.get(tmp);
        chainStepInput[20] = (byte) ((i >>> 8) & 0xFF);
        chainStepInput[21] = (byte) (i & 0xFF);
        for (int j = a; j < maxDigit; j++) {
          chainStepInput[22] = (byte) j;
          System.arraycopy(tmp, 0, chainStepInput, 23, n);
          tmp = sha256.digest(chainStepInput);
        }
        kcDigest.update(tmp);
      }
      byte[] kc = kcDigest.digest();

      int sigLmsType = sigBuf.getInt();
      if (sigLmsType != pubLmsType) {
        return false;
      }

      int nodeNum = (1 << h) + q;
      sha256.reset();
      sha256.update(treeId);
      sha256.update(u32str(nodeNum));
      sha256.update(D_LEAF);
      sha256.update(kc);
      byte[] tmp = sha256.digest();

      for (int level = 0; level < h; level++) {
        byte[] pathNode = new byte[32];
        sigBuf.get(pathNode);
        sha256.reset();
        sha256.update(treeId);
        sha256.update(u32str(nodeNum >>> 1));
        sha256.update(D_INTR);
        if ((nodeNum & 1) == 1) {
          sha256.update(pathNode);
          sha256.update(tmp);
        } else {
          sha256.update(tmp);
          sha256.update(pathNode);
        }
        tmp = sha256.digest();
        nodeNum >>>= 1;
      }

      return MessageDigest.isEqual(tmp, rootHash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (Exception e) {
      return false;
    }
  }

  private static int getLmsHeight(int lmsType) {
    switch (lmsType) {
      case 5:
        return 5;
      case 6:
        return 10;
      case 7:
        return 15;
      case 8:
        return 20;
      case 9:
        return 25;
      default:
        return -1;
    }
  }

  private static int[] getLmotsParams(int lmotsType) {
    switch (lmotsType) {
      case 1:
        return new int[] {32, 1, 265, 7};
      case 2:
        return new int[] {32, 2, 133, 6};
      case 3:
        return new int[] {32, 4, 67, 4};
      case 4:
        return new int[] {32, 8, 34, 0};
      default:
        return null;
    }
  }

  private static int coef(byte[] s, int i, int w) {
    if (w == 8) {
      return s[i] & 0xFF;
    } else if (w == 4) {
      int b = s[i >>> 1] & 0xFF;
      return (i & 1) == 0 ? (b >>> 4) & 0x0F : b & 0x0F;
    } else if (w == 2) {
      int b = s[i >>> 2] & 0xFF;
      int shift = 6 - 2 * (i & 3);
      return (b >>> shift) & 0x03;
    } else if (w == 1) {
      int b = s[i >>> 3] & 0xFF;
      int shift = 7 - (i & 7);
      return (b >>> shift) & 0x01;
    }
    throw new IllegalArgumentException("Unsupported w: " + w);
  }

  private static int cksm(byte[] qHash, int w, int n, int ls) {
    int total = 0;
    int maxDigit = (1 << w) - 1;
    int numDigits = (8 * n) / w;
    for (int i = 0; i < numDigits; i++) {
      total += maxDigit - coef(qHash, i, w);
    }
    return (total << ls) & 0xFFFF;
  }

  private static byte[] u32str(int v) {
    byte[] b = new byte[4];
    putInt32(b, 0, v);
    return b;
  }

  private static void putInt32(byte[] buf, int offset, int v) {
    buf[offset] = (byte) ((v >>> 24) & 0xFF);
    buf[offset + 1] = (byte) ((v >>> 16) & 0xFF);
    buf[offset + 2] = (byte) ((v >>> 8) & 0xFF);
    buf[offset + 3] = (byte) (v & 0xFF);
  }

  private static void putUint48(ByteBuffer buf, long v) {
    buf.put((byte) ((v >>> 40) & 0xFF));
    buf.put((byte) ((v >>> 32) & 0xFF));
    buf.put((byte) ((v >>> 24) & 0xFF));
    buf.put((byte) ((v >>> 16) & 0xFF));
    buf.put((byte) ((v >>> 8) & 0xFF));
    buf.put((byte) (v & 0xFF));
  }

  private static boolean containsSubsequence(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }
}
