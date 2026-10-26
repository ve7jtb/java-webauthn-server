package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.attestation.mtc.FidoMtcLogEntry;
import com.yubico.webauthn.attestation.mtc.MerkleInclusion;
import com.yubico.webauthn.attestation.mtc.MtcAttestationInfo;
import com.yubico.webauthn.attestation.mtc.MtcAttestationInfo.KeySource;
import com.yubico.webauthn.attestation.mtc.MtcBatchKeyEntry;
import com.yubico.webauthn.attestation.mtc.MtcCertDescriptor;
import com.yubico.webauthn.attestation.mtc.MtcProof;
import com.yubico.webauthn.attestation.mtc.MtcSubtree;
import com.yubico.webauthn.attestation.mtc.MtcTrustAnchor;
import com.yubico.webauthn.attestation.mtc.MtcTrustSource;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorRegistrationExtensionOutputs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Verifies WebAuthn Merkle Tree Certificate ({@code fmt: "mtc"}, and legacy alias {@code
 * "mtc-mds"}) attestation statements.
 *
 * <p>In this format, the attestation public key is omitted from {@code attStmt} on the wire:
 *
 * <ul>
 *   <li>For <b>Batch Attestation</b>, the attestation public key comes from FIDO MDS3 ({@link
 *       MtcTrustAnchor#getBatchKeys()}), or in conformance testing from {@code mtc-debug} verified
 *       against an MDS subtree root hash via {@code mtcProof}.
 *   <li>For <b>Enterprise Attestation</b>, the attestation public key and {@code deviceSerial} come
 *       either from an enterprise vendor key manifest or from the {@code mtc-debug} authenticator
 *       extension verified against an MDS subtree root hash via {@code mtcProof}.
 * </ul>
 */
final class MtcAttestationStatementVerifier {

  @Value
  @Builder
  static class MtcVerificationResult {
    boolean signatureValid;
    boolean trusted;
    @NonNull AttestationType attestationType;
    @NonNull MtcAttestationInfo mtcAttestationInfo;
  }

  public MtcVerificationResult verifyMtcAttestation(
      @NonNull AttestationObject attestation,
      @NonNull ByteArray clientDataJsonHash,
      @NonNull Optional<MtcTrustSource> mtcTrustSource,
      @NonNull Clock clock,
      @NonNull AttestationConveyancePreference requestedConveyance) {
    return verifyMtcAttestation(
        attestation,
        clientDataJsonHash,
        mtcTrustSource,
        clock,
        requestedConveyance,
        Optional.empty());
  }

  public MtcVerificationResult verifyMtcAttestation(
      @NonNull AttestationObject attestation,
      @NonNull ByteArray clientDataJsonHash,
      @NonNull Optional<MtcTrustSource> mtcTrustSource,
      @NonNull Clock clock,
      @NonNull AttestationConveyancePreference requestedConveyance,
      @NonNull Optional<MtcDebugRegistrationOutput> clientMtcDebugOpt) {

    JsonNode attStmt = attestation.getAttestationStatement();
    if (attStmt.has("pubKey")) {
      throw new IllegalArgumentException(
          "fmt \"mtc\" must not contain an inline \"pubKey\" in attStmt.");
    }

    JsonNode algNode = attStmt.get("alg");
    if (algNode == null || !algNode.canConvertToLong()) {
      throw new IllegalArgumentException("\"alg\" in mtc attStmt must be a COSE algorithm integer.");
    }
    COSEAlgorithmIdentifier alg =
        COSEAlgorithmIdentifier.fromId(algNode.longValue())
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "Unsupported COSE algorithm in mtc attStmt: " + algNode.longValue()));

    JsonNode sigNode = attStmt.get("sig");
    if (sigNode == null || (!sigNode.isBinary() && !sigNode.isTextual())) {
      throw new IllegalArgumentException("\"sig\" in mtc attStmt must be a byte string.");
    }
    final ByteArray sig;
    try {
      sig = new ByteArray(sigNode.binaryValue());
    } catch (IOException e) {
      throw new IllegalArgumentException("Failed to decode \"sig\" in mtc attStmt.", e);
    }

    JsonNode mtcCertNode = attStmt.get("mtcCert");
    if (mtcCertNode == null || !mtcCertNode.isObject()) {
      throw new IllegalArgumentException("\"mtcCert\" in mtc attStmt must be a CBOR map.");
    }
    MtcCertDescriptor mtcCert = MtcCertDescriptor.fromJsonNode(mtcCertNode);

    AttestedCredentialData credentialData =
        attestation
            .getAuthenticatorData()
            .getAttestedCredentialData()
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "MTC attestation requires attestedCredentialData."));
    ByteArray aaguid = credentialData.getAaguid();

    Optional<MtcDebugRegistrationOutput> authDataMtcDebugOpt =
        AuthenticatorRegistrationExtensionOutputs.fromAuthenticatorData(
                attestation.getAuthenticatorData())
            .flatMap(AuthenticatorRegistrationExtensionOutputs::getMtcDebug);

    if (clientMtcDebugOpt.isPresent()
        && clientMtcDebugOpt.get().getDeviceSerial().isPresent()
        && requestedConveyance != AttestationConveyancePreference.ENTERPRISE) {
      throw new IllegalArgumentException(
          "clientExtensionResults.mtcDebug contains deviceSerial when attestation conveyance is not enterprise.");
    }

    if (authDataMtcDebugOpt.isPresent() && clientMtcDebugOpt.isPresent()) {
      MtcDebugRegistrationOutput authDbg = authDataMtcDebugOpt.get();
      MtcDebugRegistrationOutput clientDbg = clientMtcDebugOpt.get();
      ByteArray authKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(authDbg.getPubKey());
      ByteArray clientKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(clientDbg.getPubKey());
      if (!authKeyHash.equals(clientKeyHash)) {
        throw new IllegalArgumentException(
            "clientExtensionResults.mtcDebug.pubKey does not match authenticatorData mtc-debug pubKey.");
      }
      if (!authDbg.getDeviceSerial().equals(clientDbg.getDeviceSerial())) {
        throw new IllegalArgumentException(
            "clientExtensionResults.mtcDebug.deviceSerial does not match authenticatorData mtc-debug deviceSerial.");
      }
    }

    Optional<MtcDebugRegistrationOutput> mtcDebugOpt =
        authDataMtcDebugOpt.isPresent() ? authDataMtcDebugOpt : clientMtcDebugOpt;

    if (mtcDebugOpt.isPresent()
        && mtcDebugOpt.get().getDeviceSerial().isPresent()
        && requestedConveyance != AttestationConveyancePreference.ENTERPRISE) {
      throw new IllegalArgumentException(
          "mtc-debug extension contains deviceSerial when attestation conveyance is not enterprise.");
    }

    // Cross-check mtcCert fields with mtcDebug fields when both are present
    if (mtcDebugOpt.isPresent()) {
      MtcDebugRegistrationOutput dbg = mtcDebugOpt.get();
      if (mtcCert.getNotBefore().isPresent()
          && dbg.getNotBefore().isPresent()
          && !mtcCert.getNotBefore().get().equals(dbg.getNotBefore().get())) {
        throw new IllegalArgumentException(
            "mtc-debug notBefore does not match mtcCert.notBefore.");
      }
      if (mtcCert.getNotAfter().isPresent()
          && dbg.getNotAfter().isPresent()
          && !mtcCert.getNotAfter().get().equals(dbg.getNotAfter().get())) {
        throw new IllegalArgumentException("mtc-debug notAfter does not match mtcCert.notAfter.");
      }
      if (mtcCert.getFirmwareVersion().isPresent()
          && dbg.getFirmwareVersion().isPresent()
          && !mtcCert.getFirmwareVersion().get().equals(dbg.getFirmwareVersion().get())) {
        throw new IllegalArgumentException(
            "mtc-debug firmwareVersion does not match mtcCert.firmwareVersion.");
      }
      if (mtcCert.getMtcProof().isPresent()
          && dbg.getMtcProof().isPresent()
          && !mtcCert.getMtcProof().get().equals(dbg.getMtcProof().get())) {
        throw new IllegalArgumentException("mtc-debug mtcProof does not match mtcCert.mtcProof.");
      }
    }

    Optional<ByteArray> effectiveMtcProof =
        mtcCert.getMtcProof().isPresent()
            ? mtcCert.getMtcProof()
            : mtcDebugOpt.flatMap(MtcDebugRegistrationOutput::getMtcProof);

    Optional<MtcTrustAnchor> anchorOpt =
        mtcTrustSource.flatMap(ts -> ts.findMtcTrustAnchor(mtcCert.getCaId(), Optional.of(aaguid)));

    ByteArray cosePubKey;
    String deviceSerial = null;
    KeySource keySource;
    Optional<MtcBatchKeyEntry> resolvedBatchKeyEntry = Optional.empty();

    if (anchorOpt.isPresent()) {
      MtcTrustAnchor anchor = anchorOpt.get();
      if (anchor.getAaguid().isPresent() && !anchor.getAaguid().get().equals(aaguid)) {
        throw new IllegalArgumentException(
            String.format(
                "Authenticator AAGUID %s does not match MTC trust anchor AAGUID %s.",
                aaguid.getHex(), anchor.getAaguid().get().getHex()));
      }
      if (anchor.getRevokedSerials().contains(mtcCert.getSerial())) {
        throw new IllegalArgumentException(
            "MTC attestation certificate serial is revoked: " + mtcCert.getSerial());
      }
      if (anchor.getLogNumber().isPresent()
          && anchor.getLogNumber().get() != mtcCert.getLogNumber()) {
        throw new IllegalArgumentException(
            String.format(
                "MTC serial logNumber %d does not match trust anchor logNumber %d.",
                mtcCert.getLogNumber(), anchor.getLogNumber().get()));
      }

      resolvedBatchKeyEntry = anchor.findBatchKey(mtcCert.getSerial());
      if (resolvedBatchKeyEntry.isPresent()) {
        cosePubKey = resolvedBatchKeyEntry.get().getCoseKey();
        deviceSerial = resolvedBatchKeyEntry.get().getDeviceSerial().orElse(null);
        keySource =
            resolvedBatchKeyEntry.get().getDeviceSerial().isPresent()
                ? KeySource.ENTERPRISE_MANIFEST
                : KeySource.MDS_BATCH_KEY_TABLE;

        if (mtcDebugOpt.isPresent()) {
          ByteArray expectedHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(cosePubKey);
          ByteArray debugHash =
              FidoMtcLogEntry.computeCanonicalCoseKeyHash(mtcDebugOpt.get().getPubKey());
          if (!expectedHash.equals(debugHash)) {
            throw new IllegalArgumentException(
                "mtc-debug pubKey does not match trusted batchKey for serial "
                    + mtcCert.getSerial());
          }
          if (mtcDebugOpt.get().getDeviceSerial().isPresent()
              && deviceSerial != null
              && !deviceSerial.equals(mtcDebugOpt.get().getDeviceSerial().get())) {
            throw new IllegalArgumentException(
                "mtc-debug deviceSerial does not match enterprise manifest deviceSerial.");
          }
        }
      } else if (mtcDebugOpt.isPresent()) {
        if (!effectiveMtcProof.isPresent()) {
          throw new IllegalArgumentException(
              "mtc-debug key resolution requires mtcProof (in mtcCert or mtc-debug) to bind key to MDS subtree root.");
        }
        cosePubKey = mtcDebugOpt.get().getPubKey();
        deviceSerial = mtcDebugOpt.get().getDeviceSerial().orElse(null);
        keySource = KeySource.MTC_DEBUG_EXTENSION;
      } else {
        throw new IllegalArgumentException(
            String.format(
                "MTC public key for caId %s, serial %d not found in MDS/manifest batchKeys or mtc-debug extension.",
                mtcCert.getCaId().getBase64Url(), mtcCert.getSerial()));
      }
    } else if (mtcDebugOpt.isPresent()) {
      cosePubKey = mtcDebugOpt.get().getPubKey();
      deviceSerial = mtcDebugOpt.get().getDeviceSerial().orElse(null);
      keySource = KeySource.MTC_DEBUG_EXTENSION;
    } else {
      throw new IllegalArgumentException(
          String.format(
              "No trusted MtcTrustAnchor or mtc-debug extension available for caId %s, serial %d.",
              mtcCert.getCaId().getBase64Url(), mtcCert.getSerial()));
    }

    Optional<Long> effectiveNotBefore =
        mtcCert.getNotBefore().isPresent()
            ? mtcCert.getNotBefore()
            : (resolvedBatchKeyEntry.flatMap(MtcBatchKeyEntry::getNotBefore).isPresent()
                ? resolvedBatchKeyEntry.flatMap(MtcBatchKeyEntry::getNotBefore)
                : mtcDebugOpt.flatMap(MtcDebugRegistrationOutput::getNotBefore));

    Optional<Long> effectiveNotAfter =
        mtcCert.getNotAfter().isPresent()
            ? mtcCert.getNotAfter()
            : (resolvedBatchKeyEntry.flatMap(MtcBatchKeyEntry::getNotAfter).isPresent()
                ? resolvedBatchKeyEntry.flatMap(MtcBatchKeyEntry::getNotAfter)
                : mtcDebugOpt.flatMap(MtcDebugRegistrationOutput::getNotAfter));

    Optional<Long> effectiveFirmwareVersion =
        mtcCert.getFirmwareVersion().isPresent()
            ? mtcCert.getFirmwareVersion()
            : (resolvedBatchKeyEntry.flatMap(MtcBatchKeyEntry::getFirmwareVersion).isPresent()
                ? resolvedBatchKeyEntry.flatMap(MtcBatchKeyEntry::getFirmwareVersion)
                : mtcDebugOpt.flatMap(MtcDebugRegistrationOutput::getFirmwareVersion));

    Optional<COSEAlgorithmIdentifier> keyAlgOpt =
        COSEAlgorithmIdentifier.fromPublicKey(cosePubKey);
    if (keyAlgOpt.isPresent() && keyAlgOpt.get() != alg) {
      throw new IllegalArgumentException(
          String.format(
              "MTC attStmt alg %s does not match resolved COSE_Key alg %s.",
              alg, keyAlgOpt.get()));
    }

    final PublicKey pubKey;
    try {
      pubKey = WebAuthnCodecs.importCosePublicKey(cosePubKey);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to decode MTC attestation COSE_Key.", e);
    }

    ByteArray signedBytes =
        attestation.getAuthenticatorData().getBytes().concat(clientDataJsonHash);
    if (!Crypto.verifySignature(pubKey, signedBytes, sig, alg)
        && !Crypto.verifySignature(pubKey, Crypto.sha256(signedBytes), sig, alg)) {
      throw new IllegalArgumentException("Invalid MTC attestation signature.");
    }

    // Validity window check (WebAuthn L4 §8.10 Step 7.1 & 7.2)
    if (effectiveNotBefore.isPresent() && effectiveNotAfter.isPresent()) {
      long notBefore = effectiveNotBefore.get();
      long notAfter = effectiveNotAfter.get();
      if (notAfter < notBefore) {
        throw new IllegalArgumentException("MTC certificate notAfter is before notBefore.");
      }
      long nowEpochSeconds = clock.instant().getEpochSecond();
      if (nowEpochSeconds < notBefore || nowEpochSeconds > notAfter) {
        throw new IllegalArgumentException(
            String.format(
                "MTC certificate is outside validity window [%d, %d] at %d.",
                notBefore, notAfter, nowEpochSeconds));
      }
      if (anchorOpt.isPresent()
          && anchorOpt.get().getMaxBatchWindow().isPresent()
          && notAfter != 253402300799L) {
        long maxWindow = anchorOpt.get().getMaxBatchWindow().get();
        if (notAfter - notBefore > maxWindow) {
          throw new IllegalArgumentException(
              String.format(
                  "MTC certificate validity window %d exceeds maxBatchWindow %d.",
                  notAfter - notBefore, maxWindow));
        }
      }
    }

    boolean trusted = false;
    boolean proofVerified = false;
    ByteArray subtreeRootHash = null;
    ByteArray leafHash = null;

    if (effectiveMtcProof.isPresent()) {
      if (!effectiveNotBefore.isPresent() || !effectiveNotAfter.isPresent()) {
        throw new IllegalArgumentException(
            "MTC inclusion proof verification requires notBefore and notAfter (in mtcCert, manifest, or mtc-debug).");
      }
      MtcProof proof = MtcProof.parse(effectiveMtcProof.get());
      if (proof.getSignatures().getBytes().length != 0) {
        throw new IllegalArgumentException(
            "Abridged FIDO MTC proof must have empty signatures array.");
      }

      byte[] proofExtBytes = proof.getExtensions().getBytes();
      if (proofExtBytes.length > 0) {
        if (requestedConveyance != AttestationConveyancePreference.ENTERPRISE) {
          throw new IllegalArgumentException(
              "Enterprise MTC proof extensions present when enterprise conveyance was not requested.");
        }
        String proofSerial = new String(proofExtBytes, StandardCharsets.UTF_8);
        if (deviceSerial != null && !deviceSerial.equals(proofSerial)) {
          throw new IllegalArgumentException(
              String.format(
                  "Device serial mismatch between resolved key (%s) and MTCProof extensions (%s).",
                  deviceSerial, proofSerial));
        }
        deviceSerial = proofSerial;
      } else if (deviceSerial != null) {
        throw new IllegalArgumentException(
            "Resolved enterprise deviceSerial is present, but MTCProof.extensions is empty.");
      }

      ByteArray pubKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(cosePubKey);
      FidoMtcLogEntry logEntry =
          FidoMtcLogEntry.builder()
              .caId(mtcCert.getCaId())
              .serial(mtcCert.getSerial())
              .notBefore(effectiveNotBefore.get())
              .notAfter(effectiveNotAfter.get())
              .aaguid(aaguid)
              .fwVersion(effectiveFirmwareVersion)
              .pubKeyHash(pubKeyHash)
              .extensions(proof.getExtensions())
              .build();

      leafHash = logEntry.computeLeafHash();
      ByteArray computedRoot =
          MerkleInclusion.evaluateInclusionProof(
                  mtcCert.getLeafIndex(),
                  proof.getStart(),
                  proof.getEnd(),
                  leafHash,
                  proof.getInclusionProof())
              .orElseThrow(
                  () -> new IllegalArgumentException("Failed to evaluate MTC inclusion proof."));

      Optional<ByteArray> debugRootHashOpt =
          mtcDebugOpt.flatMap(MtcDebugRegistrationOutput::getRootHash);

      if (anchorOpt.isPresent()) {
        MtcTrustAnchor anchor = anchorOpt.get();
        MtcSubtree matchingSubtree =
            anchor.getSubtrees().stream()
                .filter(
                    st ->
                        st.getStart() == proof.getStart()
                            && st.getEnd() == proof.getEnd()
                            && st.getLogNumber()
                                .map(ln -> ln == mtcCert.getLogNumber())
                                .orElse(true))
                .findFirst()
                .orElseThrow(
                    () ->
                        new IllegalArgumentException(
                            String.format(
                                "No matching MTC subtree for [%d, %d) in trust anchor %s.",
                                proof.getStart(),
                                proof.getEnd(),
                                mtcCert.getCaId().getBase64Url())));

        if (!computedRoot.equals(matchingSubtree.getRootHash())) {
          throw new IllegalArgumentException(
              String.format(
                  "MTC Merkle root hash mismatch: computed %s, expected %s.",
                  computedRoot.getBase64Url(), matchingSubtree.getRootHash().getBase64Url()));
        }
        if (debugRootHashOpt.isPresent()
            && !debugRootHashOpt.get().equals(matchingSubtree.getRootHash())) {
          throw new IllegalArgumentException(
              String.format(
                  "mtc-debug rootHash %s does not match trust anchor subtree rootHash %s.",
                  debugRootHashOpt.get().getBase64Url(),
                  matchingSubtree.getRootHash().getBase64Url()));
        }

        subtreeRootHash = matchingSubtree.getRootHash();
        proofVerified = true;
        trusted = true;
      } else if (debugRootHashOpt.isPresent()) {
        // Standalone offline conformance verification against mtcDebug.rootHash
        if (!computedRoot.equals(debugRootHashOpt.get())) {
          throw new IllegalArgumentException(
              String.format(
                  "MTC offline Merkle root hash mismatch: computed %s, expected mtc-debug rootHash %s.",
                  computedRoot.getBase64Url(), debugRootHashOpt.get().getBase64Url()));
        }
        subtreeRootHash = debugRootHashOpt.get();
        proofVerified = true;
      }
    } else if (anchorOpt.isPresent()) {
      MtcTrustAnchor anchor = anchorOpt.get();
      // Proof-less mtcKeyRef mode without mtcDebug.mtcProof: requires authenticated MDS or enterprise manifest key table
      if (!anchor.isKeyTableAuthenticated() || keySource == KeySource.MTC_DEBUG_EXTENSION) {
        throw new IllegalArgumentException(
            "Proof-less mtcKeyRef requires an authenticated MDS or enterprise manifest key table (or mtcProof in mtc-debug).");
      }
      if (deviceSerial != null
          && requestedConveyance != AttestationConveyancePreference.ENTERPRISE) {
        throw new IllegalArgumentException(
            "Enterprise MTC key resolved when enterprise conveyance was not requested.");
      }
      trusted = true;
    }

    boolean isEnterprise = deviceSerial != null;
    if (isEnterprise && requestedConveyance != AttestationConveyancePreference.ENTERPRISE) {
      throw new IllegalArgumentException(
          "Enterprise MTC attestation cannot be accepted unless enterprise conveyance was requested.");
    }

    MtcAttestationInfo info =
        MtcAttestationInfo.builder()
            .caId(mtcCert.getCaId())
            .serial(mtcCert.getSerial())
            .logNumber(mtcCert.getLogNumber())
            .leafIndex(mtcCert.getLeafIndex())
            .notBefore(effectiveNotBefore.orElse(null))
            .notAfter(effectiveNotAfter.orElse(null))
            .fwVersion(effectiveFirmwareVersion.orElse(null))
            .subtreeRootHash(subtreeRootHash)
            .leafHash(leafHash)
            .deviceSerial(deviceSerial)
            .enterprise(isEnterprise)
            .proofVerified(proofVerified)
            .keySource(keySource)
            .build();

    return MtcVerificationResult.builder()
        .signatureValid(true)
        .trusted(trusted)
        .attestationType(isEnterprise ? AttestationType.ATTESTATION_CA : AttestationType.BASIC)
        .mtcAttestationInfo(info)
        .build();
  }
}
