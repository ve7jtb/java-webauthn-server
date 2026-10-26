// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package demo.webauthn;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.fido.metadata.FidoMetadataDownloader;
import com.yubico.fido.metadata.FidoMetadataDownloaderException;
import com.yubico.fido.metadata.FidoMetadataService;
import com.yubico.fido.metadata.UnexpectedLegalHeader;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.util.Either;
import com.yubico.webauthn.AssertionResultV2;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.RelyingPartyV2;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.attestation.YubicoJsonMetadataService;
import com.yubico.webauthn.attestation.mtc.CompositeMtcTrustSource;
import com.yubico.webauthn.attestation.mtc.FidoMtcLogEntry;
import com.yubico.webauthn.attestation.mtc.MtcAttestationInfo;
import com.yubico.webauthn.attestation.mtc.MtcBatchKeyEntry;
import com.yubico.webauthn.attestation.mtc.MtcCheckpoint;
import com.yubico.webauthn.attestation.mtc.MtcJsonTrustSource;
import com.yubico.webauthn.attestation.mtc.MtcSubtree;
import com.yubico.webauthn.attestation.mtc.MtcTrustAnchor;
import com.yubico.webauthn.attestation.mtc.MtcTrustSource;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import demo.webauthn.data.AssertionRequestWrapper;
import demo.webauthn.data.AssertionResponse;
import demo.webauthn.data.CredentialRegistration;
import demo.webauthn.data.RegistrationRequest;
import demo.webauthn.data.RegistrationResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.Value;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebAuthnServer {
  private static final Logger logger = LoggerFactory.getLogger(WebAuthnServer.class);
  private static final SecureRandom random = new SecureRandom();

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private final Cache<ByteArray, AssertionRequestWrapper> assertRequestStorage;
  private final Cache<ByteArray, RegistrationRequest> registerRequestStorage;
  private final InMemoryRegistrationStorage userStorage;
  private final SessionManager sessions = new SessionManager();

  private final MetadataService baseMetadataService = getMetadataService();
  private final Map<ByteArray, MtcTrustAnchor> activeMtcAnchors = new LinkedHashMap<>();
  private final Set<X509Certificate> dynamicX509TrustRoots = new LinkedHashSet<>();
  private final Map<ByteArray, Map<String, Object>> dynamicStatementEntriesByAaguid =
      new LinkedHashMap<>();

  private final MetadataService metadataService =
      new MetadataService() {
        @Override
        public TrustRootsResult findTrustRoots(
            List<X509Certificate> attestationCertificateChain, Optional<ByteArray> aaguid) {
          TrustRootsResult baseResult =
              baseMetadataService.findTrustRoots(attestationCertificateChain, aaguid);
          Set<X509Certificate> combined = new LinkedHashSet<>(baseResult.getTrustRoots());
          synchronized (activeMtcAnchors) {
            combined.addAll(dynamicX509TrustRoots);
          }
          return TrustRootsResult.builder()
              .trustRoots(combined)
              .enableRevocationChecking(baseResult.isEnableRevocationChecking())
              .build();
        }

        @Override
        public Set<Object> findEntries(@NonNull RegistrationResult registrationResult) {
          Set<Object> baseEntries = baseMetadataService.findEntries(registrationResult);
          if (!baseEntries.isEmpty()) {
            return baseEntries;
          }
          Set<Object> dynamicEntries = new LinkedHashSet<>();
          synchronized (activeMtcAnchors) {
            Optional.ofNullable(dynamicStatementEntriesByAaguid.get(registrationResult.getAaguid()))
                .ifPresent(dynamicEntries::add);
          }
          return dynamicEntries;
        }
      };

  private final MtcTrustSource mtcTrustSource =
      (caId, aaguid) -> {
        synchronized (activeMtcAnchors) {
          MtcTrustAnchor candidate = activeMtcAnchors.get(caId);
          if (candidate == null) {
            return Optional.empty();
          }
          if (!candidate.getAaguid().isPresent()
              || !aaguid.isPresent()
              || candidate.getAaguid().get().equals(aaguid.get())) {
            return Optional.of(candidate);
          }
          return Optional.empty();
        }
      };

  private static MetadataService getMetadataService()
      throws CertPathValidatorException,
          InvalidAlgorithmParameterException,
          Base64UrlException,
          DigestException,
          FidoMetadataDownloaderException,
          CertificateException,
          UnexpectedLegalHeader,
          IOException,
          NoSuchAlgorithmException,
          SignatureException,
          InvalidKeyException {
    if (Config.useFidoMds()) {
      logger.info("Using combination of Yubico JSON file and FIDO MDS for attestation metadata.");
      return new CompositeMetadataService(
          new YubicoJsonMetadataService(),
          new FidoMetadataServiceAdapter(
              FidoMetadataService.builder()
                  .useBlob(
                      FidoMetadataDownloader.builder()
                          .expectLegalHeader(
                              "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/")
                          .useDefaultTrustRoot()
                          .useTrustRootCacheFile(
                              new File("webauthn-server-demo-fido-mds-trust-root-cache.bin"))
                          .useDefaultBlob()
                          .useBlobCacheFile(
                              new File("webauthn-server-demo-fido-mds-blob-cache.bin"))
                          .build()
                          .loadCachedBlob())
                  .build()));
    } else {
      logger.info("Using only Yubico JSON file for attestation metadata.");
      return new YubicoJsonMetadataService();
    }
  }

  private final Clock clock = Clock.systemDefaultZone();
  private final ObjectMapper jsonMapper = JacksonCodecs.json();

  private final RelyingPartyV2<CredentialRegistration> rp;

  public WebAuthnServer()
      throws CertificateException,
          CertPathValidatorException,
          InvalidAlgorithmParameterException,
          Base64UrlException,
          DigestException,
          FidoMetadataDownloaderException,
          UnexpectedLegalHeader,
          IOException,
          NoSuchAlgorithmException,
          SignatureException,
          InvalidKeyException {
    this(
        new InMemoryRegistrationStorage(),
        newCache(),
        newCache(),
        Config.getRpIdentity(),
        Config.getOrigins());
  }

  public WebAuthnServer(
      InMemoryRegistrationStorage userStorage,
      Cache<ByteArray, RegistrationRequest> registerRequestStorage,
      Cache<ByteArray, AssertionRequestWrapper> assertRequestStorage,
      RelyingPartyIdentity rpIdentity,
      Set<String> origins)
      throws CertificateException,
          CertPathValidatorException,
          InvalidAlgorithmParameterException,
          Base64UrlException,
          DigestException,
          FidoMetadataDownloaderException,
          UnexpectedLegalHeader,
          IOException,
          NoSuchAlgorithmException,
          SignatureException,
          InvalidKeyException {
    this.userStorage = userStorage;
    this.registerRequestStorage = registerRequestStorage;
    this.assertRequestStorage = assertRequestStorage;

    resetMetadataToDefaults();

    rp =
        RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepositoryV2(this.userStorage)
            .usernameRepository(this.userStorage)
            .origins(origins)
            .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
            .attestationFormats("mtc", "packed")
            .attestationTrustSource(metadataService)
            .mtcTrustSource(mtcTrustSource)
            .allowOriginPort(false)
            .allowOriginSubdomain(false)
            .allowUntrustedAttestation(true)
            .validateSignatureCounter(true)
            .build();
  }

  // Demo MTC constants from Fidont OpenSK
  private static final ByteArray FIDONT_AAGUID;
  private static final ByteArray DEMO_BATCH_CA_ID; // g5k_AQM
  private static final ByteArray ENTERPRISE_CA_ID; // g5k_AQI
  private static final ByteArray ENTERPRISE_MANIFEST_CA_ID; // g5k_AQQ
  private static final long DEMO_SERIAL = 1970324836974592L; // (7L << 48) | 0L
  private static final long DEMO_NOT_BEFORE = 1792281600L;
  private static final long DEMO_NOT_AFTER = 2107641600L;
  private static final String DEMO_DEVICE_SERIAL = "123456";

  private static final String FIDONT_ENTERPRISE_COSE_KEY_B64 =
      "owEHAzgvIFkFINzYZIhJKP3OLxMPdmyU1f8bD5Drf3ZdXIGb0RnVNic4T947v8FBsceKALZ5WDYhaztebO08ntMVXBH7V2OlNMWbzXfzuy8poYZuqgZUV9EwJJIg4T2t0cAW3gXScvC2UaJn1In32wPSGh12nTDpu3lT3U7yN47XUTbUdqrA0hc33M3rZq-aDbacOj_X1m7mGcvdp_u6slrrCAby9gKz1sLFOmF2EHFpfbtPkwT8jTNkvxW8puQdoWPYpUkNkVV5RRkNpN9Q75whss4x8i0HXVuddJXj_B-ByKQ742kQCWVz2uNeNhIzpeV7vNXcRfhbHLnRt_9vMPRyZqfr44JsgQNZppT9mAnhG4lgl2QgoLfA29N8O55172LPdanlMggbqreSaL3nnUoqjNMmkOe09XnFRhKi-O7UncLNFNDPwsRvXLlKwEZLfAyZVkCWilMTbDO1cKrrw8DMFAJhoMQde2ujjOLNTmC9NfChq7mLC0bBqSYfiOztlunetIGyB3RBEHV_07ePlzC205eKzb5TS8UkI7x3ZqyT1QA5X7eOduRg6dailUj2qfZBHvTaKKcULJgsk8CjPAzBk3_k2C4mOIWg8rAfd62JPHdJoTazQc88N13ySdsYNRt5IFryu4NWLE8l85X4VfGf-qkeo44tDJF1dGrU7cJhIrd_-Ur_np2fdzDnHcMyNrI-gZOCofNR5zqZdhe7qcrOQmFhkPaj9A_spZmFst0yzeC3zW9H97sS8SrBBTLNDWKUMXgjcBBpiTes3Y5slsbGWag24jSNKH_vSBvPp6Ot-rbaJV5hPLNZWOwkuDXKejtHzx9HNksaGbK7e1Zl-Ig2iGvajAbHOQQSUfAcMNV360xbtIy-Bn6DG4x3xYdeWsurk1FbSuvz4vFdc8jT3EPIODx7bpKdl9ZTdzXGocuPwx5SR9YxpBcNzhvQUnSL0-2Xs9Mt0P50hmkhioNp2KyRYgjNl4KBzws3ezXWwN-96TVv4j4brhKsefh-p5-YrPGI2MtCE0a8VNIqvIBHXeo5Uho2XAuUjDQ1kp8801SmmNmLEXTYCLlKkAw5vVQN7ZS-9mIU_0TawtiWrDk3A6ENFJ9WT3xNNjjhZs_JClJ_rq3VH3hLq2K2R9Uc9zFL9hX-eYmzJFNIX7KCvxWRanF0-lSy9fY_kYJa95PlbYEuvWt1ILBvu9Q4DEU-6yKAac8hHhdI0AgBfsqMWb3RYVtFrGKrqsH-TB7D2MEwULE0U1M7ehp6T3DUAOrsW5oV4sLqDPiyc40IlxYJtQiFoX2BVc_WOM3Basi3pHO5JG9ITD7b1QXZ8KD0hVDf_71AVU_2PPE7vNeN-667SSMCcNusLsnHNWrMOdj6AF0m1q_WRDYHZUlRUqnWhU8mXarGi2GuaCtZspQ7bS1FXtzxtV5F7i-dpFaJX0_DNEfPU9cBu5vwnQAuIyoeXRULe9NswbGA8Ow8PJHjU7DvMhIooKzBnCpSnfVuMRWv3UwlqYNG7Jaw10sYyEwqfAYOaaXjmrh7sL0E_TRoHVQmKkBICHqY_-dc-ViQyuwiyiNsDq2-ovnm_5fQwxX-m81i4GIBhjsTp_12ZVhVyrusmtVmHhLVNDvFYXPuxZbg4jCH3qzFAzEEmRu2h-5rwV4SXuTA6p3m0xt_ydnjsZ-28VKbQ96iuMwMgE_ZcL49zDVA9EjEbtwYrMjlU7dD2dQfH7TwO55jao5FLOyCfzyN0yTvipUrnCUOQFI6rwI";

  private static final String FIDONT_ENTERPRISE_MTC_PROOF_B64 =
      "AAYxMjM0NTYAAAAAAAAAAAAAAAgAYDOdeFo-0VVezxoncJLIuz26qPnCnCoLi6e377twN-CRz3zVZ2f2Gg2nrKCPJqGcmpb3Qc131RQ4xGB92QaNWZFlpxGWToDgq16W5Pq9W-2CCaqnvDTXXwdWbGe1aiw3vgAAAA";

  private static final String FIDONT_ENTERPRISE_ROOT_HASH_B64 =
      "iDwM02SMbYqp9JwkLasEDsEajsKImXs553CzWIA49dg";

  private static final String FIDONT_ENTERPRISE_PKCS8_B64 =
      "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";

  private static final KeyPair DEMO_BATCH_KEYPAIR;
  private static final ByteArray DEMO_BATCH_COSE_KEY;
  private static final ByteArray DEMO_BATCH_ROOT_HASH;

  static {
    try {
      FIDONT_AAGUID = ByteArray.fromHex("deadbeef000000000000deadbeef0000");
      DEMO_BATCH_CA_ID = ByteArray.fromHex("83993f0103");
      ENTERPRISE_CA_ID = ByteArray.fromHex("83993f0102");
      ENTERPRISE_MANIFEST_CA_ID = ByteArray.fromHex("83993f0104");
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      DEMO_BATCH_KEYPAIR = kpg.generateKeyPair();
      DEMO_BATCH_COSE_KEY = ecPublicKeyToCose((ECPublicKey) DEMO_BATCH_KEYPAIR.getPublic());
      ByteArray pubKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(DEMO_BATCH_COSE_KEY);
      FidoMtcLogEntry leaf =
          FidoMtcLogEntry.builder()
              .caId(DEMO_BATCH_CA_ID)
              .notBefore(DEMO_NOT_BEFORE)
              .notAfter(DEMO_NOT_AFTER)
              .aaguid(FIDONT_AAGUID)
              .fwVersion(Optional.empty())
              .pubKeyHash(pubKeyHash)
              .serial(DEMO_SERIAL)
              .extensions(new ByteArray(new byte[0]))
              .build();
      DEMO_BATCH_ROOT_HASH = leaf.computeLeafHash();
    } catch (Exception e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private static ByteArray ecPublicKeyToCose(ECPublicKey pubKey) {
    byte[] x = toUnsignedFixedLength(pubKey.getW().getAffineX().toByteArray(), 32);
    byte[] y = toUnsignedFixedLength(pubKey.getW().getAffineY().toByteArray(), 32);
    com.upokecenter.cbor.CBORObject cose = com.upokecenter.cbor.CBORObject.NewOrderedMap();
    cose.Add(1, 2); // kty: EC2
    cose.Add(3, -7); // alg: ES256
    cose.Add(-1, 1); // crv: P-256
    cose.Add(-2, x);
    cose.Add(-3, y);
    return new ByteArray(
        cose.EncodeToBytes(com.upokecenter.cbor.CBOREncodeOptions.DefaultCtap2Canonical));
  }

  private static byte[] toUnsignedFixedLength(byte[] src, int length) {
    if (src.length == length) {
      return src;
    }
    byte[] out = new byte[length];
    if (src.length > length) {
      System.arraycopy(src, src.length - length, out, 0, length);
    } else {
      System.arraycopy(src, 0, out, length - src.length, src.length);
    }
    return out;
  }

  public void resetMetadataToDefaults() {
    synchronized (activeMtcAnchors) {
      activeMtcAnchors.clear();
      dynamicX509TrustRoots.clear();
      dynamicStatementEntriesByAaguid.clear();

      try (InputStream is = WebAuthnServer.class.getResourceAsStream("/mtc-metadata.json")) {
        if (is != null) {
          JsonNode mdsRoot = jsonMapper.readTree(is);
          loadMetadataJsonNode(mdsRoot, true);
        }
      } catch (Exception e) {
        logger.warn("Failed to load /mtc-metadata.json for MTC trust source", e);
      }

      try {
        // Demo batch anchor (caId = g5k_AQM) for browser simulation of MDS batch key lookup
        MtcTrustAnchor demoBatchAnchor =
            MtcTrustAnchor.builder()
                .caId(DEMO_BATCH_CA_ID)
                .logNumber(7)
                .hashAlg("sha-256")
                .maxBatchWindow(315360000L)
                .subtrees(
                    Collections.singletonList(
                        MtcSubtree.builder()
                            .logNumber(7)
                            .start(0L)
                            .end(1L)
                            .rootHash(DEMO_BATCH_ROOT_HASH)
                            .alg(-46)
                            .signature(new ByteArray(new byte[32]))
                            .build()))
                .batchKeys(
                    Collections.singletonList(
                        MtcBatchKeyEntry.builder()
                            .serial(DEMO_SERIAL)
                            .alg(-7L)
                            .coseKey(DEMO_BATCH_COSE_KEY)
                            .build()))
                .aaguid(FIDONT_AAGUID)
                .keyTableAuthenticated(true)
                .build();
        mergeMtcAnchor(demoBatchAnchor);

        // Demo enterprise manifest anchor (caId = g5k_AQQ) combining MDS subtree rootHash with vendor manifest key + deviceSerial
        ByteArray enterpriseCoseKey = ByteArray.fromBase64Url(FIDONT_ENTERPRISE_COSE_KEY_B64);
        ByteArray enterprisePubKeyHash =
            FidoMtcLogEntry.computeCanonicalCoseKeyHash(enterpriseCoseKey);
        FidoMtcLogEntry manifestLeaf =
            FidoMtcLogEntry.builder()
                .caId(ENTERPRISE_MANIFEST_CA_ID)
                .serial(DEMO_SERIAL)
                .notBefore(DEMO_NOT_BEFORE)
                .notAfter(DEMO_NOT_AFTER)
                .aaguid(FIDONT_AAGUID)
                .fwVersion(Optional.empty())
                .pubKeyHash(enterprisePubKeyHash)
                .extensions(new ByteArray(DEMO_DEVICE_SERIAL.getBytes(StandardCharsets.UTF_8)))
                .build();
        ByteArray enterpriseManifestRootHash = manifestLeaf.computeLeafHash();
        MtcTrustAnchor enterpriseManifestAnchor =
            MtcTrustAnchor.builder()
                .caId(ENTERPRISE_MANIFEST_CA_ID)
                .logNumber(7)
                .hashAlg("sha-256")
                .maxBatchWindow(315360000L)
                .subtrees(
                    Collections.singletonList(
                        MtcSubtree.builder()
                            .logNumber(7)
                            .start(0L)
                            .end(1L)
                            .rootHash(enterpriseManifestRootHash)
                            .alg(-46)
                            .signature(new ByteArray(new byte[32]))
                            .build()))
                .batchKeys(
                    Collections.singletonList(
                        MtcBatchKeyEntry.builder()
                            .serial(DEMO_SERIAL)
                            .alg(-48L)
                            .coseKey(enterpriseCoseKey)
                            .deviceSerial(DEMO_DEVICE_SERIAL)
                            .build()))
                .aaguid(FIDONT_AAGUID)
                .keyTableAuthenticated(true)
                .build();
        mergeMtcAnchor(enterpriseManifestAnchor);
        try (InputStream entIs =
            new FileInputStream(
                "/Users/jbradley/.gemini/antigravity/scratch/opensk/crypto_data_enterprise/mtc_enterprise_info.json")) {
          loadMetadataJsonNode(jsonMapper.readTree(entIs), false);
        } catch (Exception ignored) {
          // Optional local enterprise manifest auto-load
        }
      } catch (Exception e) {
        logger.warn("Failed to initialize demo MTC anchors", e);
      }
    }
  }

  private void mergeMtcAnchor(MtcTrustAnchor incoming) {
    synchronized (activeMtcAnchors) {
      MtcTrustAnchor existing = activeMtcAnchors.get(incoming.getCaId());
      if (existing == null) {
        activeMtcAnchors.put(
            incoming.getCaId(), incoming.toBuilder().keyTableAuthenticated(true).build());
        return;
      }

      List<MtcSubtree> mergedSubtrees = new ArrayList<>(existing.getSubtrees());
      for (MtcSubtree st : incoming.getSubtrees()) {
        mergedSubtrees.removeIf(
            old ->
                old.getLogNumber().equals(st.getLogNumber())
                    && old.getStart() == st.getStart()
                    && old.getEnd() == st.getEnd());
        mergedSubtrees.add(st);
      }

      Map<Long, MtcBatchKeyEntry> batchKeyMap = new LinkedHashMap<>();
      for (MtcBatchKeyEntry bk : existing.getBatchKeys()) {
        batchKeyMap.put(bk.getSerial(), bk);
      }
      for (MtcBatchKeyEntry bk : incoming.getBatchKeys()) {
        batchKeyMap.put(bk.getSerial(), bk);
      }

      Set<Long> mergedRevoked = new LinkedHashSet<>(existing.getRevokedSerials());
      mergedRevoked.addAll(incoming.getRevokedSerials());

      MtcTrustAnchor.MtcTrustAnchorBuilder b =
          existing.toBuilder()
              .subtrees(Collections.unmodifiableList(mergedSubtrees))
              .batchKeys(Collections.unmodifiableList(new ArrayList<>(batchKeyMap.values())))
              .revokedSerials(Collections.unmodifiableSet(mergedRevoked))
              .keyTableAuthenticated(true);

      if (incoming.getLogNumber().isPresent()) {
        b.logNumber(incoming.getLogNumber().get());
      }
      if (incoming.getAaguid().isPresent()) {
        b.aaguid(incoming.getAaguid().get());
      }
      if (incoming.getMaxBatchWindow().isPresent()) {
        b.maxBatchWindow(incoming.getMaxBatchWindow().get());
      }

      activeMtcAnchors.put(incoming.getCaId(), b.build());
    }
  }

  public Either<List<String>, ObjectNode> loadMetadataJson(
      @NonNull String jsonText, boolean verifyCheckpoints) {
    try {
      JsonNode root = jsonMapper.readTree(jsonText);
      return Either.right(loadMetadataJsonNode(root, verifyCheckpoints));
    } catch (Exception e) {
      logger.warn("Failed to load metadata JSON", e);
      return Either.left(
          Collections.singletonList("Failed to parse/load metadata JSON: " + e.getMessage()));
    }
  }

  private ObjectNode loadMetadataJsonNode(@NonNull JsonNode root, boolean verifyCheckpoints)
      throws Exception {
    int loadedAnchors = 0;
    int loadedSubtrees = 0;
    int loadedBatchKeys = 0;
    int loadedX509Certs = 0;

    synchronized (activeMtcAnchors) {
      if (root.isArray()) {
        for (JsonNode item : root) {
          ObjectNode sub = loadMetadataJsonNode(item, verifyCheckpoints);
          loadedAnchors += sub.path("loadedMtcAnchors").asInt(0);
          loadedSubtrees += sub.path("loadedSubtrees").asInt(0);
          loadedBatchKeys += sub.path("loadedBatchKeys").asInt(0);
          loadedX509Certs += sub.path("loadedX509Certs").asInt(0);
        }
      } else if (root.isObject()) {
        if (root.has("entries") && root.get("entries").isArray()) {
          for (JsonNode entryNode : root.get("entries")) {
            JsonNode target =
                entryNode.has("metadataStatement") ? entryNode.get("metadataStatement") : entryNode;
            ObjectNode sub = loadMetadataJsonNode(target, verifyCheckpoints);
            loadedAnchors += sub.path("loadedMtcAnchors").asInt(0);
            loadedSubtrees += sub.path("loadedSubtrees").asInt(0);
            loadedBatchKeys += sub.path("loadedBatchKeys").asInt(0);
            loadedX509Certs += sub.path("loadedX509Certs").asInt(0);
          }
        }

        ByteArray statementAaguid = null;
        JsonNode aaguidNode = root.get("aaguid");
        if (aaguidNode != null && aaguidNode.isTextual()) {
          String raw = aaguidNode.asText().trim();
          String hex = raw.replace("-", "");
          if (hex.length() == 32 && hex.matches("[0-9a-fA-F]+")) {
            statementAaguid = ByteArray.fromHex(hex);
          } else {
            try {
              statementAaguid = ByteArray.fromBase64Url(raw);
            } catch (Exception ignored) {
            }
          }
        }

        if (statementAaguid != null && root.has("description")) {
          Map<String, Object> entry = new LinkedHashMap<>();
          entry.put("aaguid", statementAaguid.getHex());
          entry.put("description", root.path("description").asText());
          dynamicStatementEntriesByAaguid.put(statementAaguid, entry);
        }

        List<X509Certificate> rootCerts = new ArrayList<>();
        for (String certField : Arrays.asList("attestationRootCertificates", "trustedCertificates")) {
          JsonNode certsNode = root.get(certField);
          if (certsNode != null && certsNode.isArray()) {
            for (JsonNode certText : certsNode) {
              if (certText.isTextual()) {
                X509Certificate cert = CertificateParser.parsePem(certText.asText());
                rootCerts.add(cert);
                if (dynamicX509TrustRoots.add(cert)) {
                  loadedX509Certs++;
                }
              }
            }
          }
        }
        for (String certObjField : Arrays.asList("rootCaCertificate", "rootCaCertificateEs384")) {
          JsonNode certObj = root.get(certObjField);
          if (certObj != null && certObj.isObject() && certObj.hasNonNull("derBase64")) {
            X509Certificate cert =
                CertificateParser.parsePem(certObj.get("derBase64").asText());
            rootCerts.add(cert);
            if (dynamicX509TrustRoots.add(cert)) {
              loadedX509Certs++;
            }
          }
        }

        if (root.has("mtcTrustAnchors") && root.get("mtcTrustAnchors").isArray()) {
          if (verifyCheckpoints && !rootCerts.isEmpty()) {
            MtcJsonTrustSource parsedSource = MtcJsonTrustSource.fromMetadataStatementNode(root);
            for (MtcTrustAnchor anchor : parsedSource.getAnchors()) {
              mergeMtcAnchor(anchor);
              loadedAnchors++;
              loadedSubtrees += anchor.getSubtrees().size();
              loadedBatchKeys += anchor.getBatchKeys().size();
            }
          } else {
            for (JsonNode anchorNode : root.get("mtcTrustAnchors")) {
              MtcTrustAnchor rawAnchor = jsonMapper.treeToValue(anchorNode, MtcTrustAnchor.class);
              MtcTrustAnchor.MtcTrustAnchorBuilder b =
                  rawAnchor.toBuilder().keyTableAuthenticated(true);
              if (!rawAnchor.getAaguid().isPresent() && statementAaguid != null) {
                b.aaguid(statementAaguid);
              }
              MtcTrustAnchor built = b.build();
              mergeMtcAnchor(built);
              loadedAnchors++;
              loadedSubtrees += built.getSubtrees().size();
              loadedBatchKeys += built.getBatchKeys().size();
            }
          }
        }

        for (String singleAnchorField :
            Arrays.asList("mtcTrustAnchor", "enterpriseInventoryManifest")) {
          if (root.has(singleAnchorField) && root.get(singleAnchorField).isObject()) {
            JsonNode anchorNode = root.get(singleAnchorField);
            MtcTrustAnchor rawAnchor = jsonMapper.treeToValue(anchorNode, MtcTrustAnchor.class);
            MtcTrustAnchor.MtcTrustAnchorBuilder b =
                rawAnchor.toBuilder().keyTableAuthenticated(true);
            if (!rawAnchor.getAaguid().isPresent() && statementAaguid != null) {
              b.aaguid(statementAaguid);
            }
            MtcTrustAnchor built = b.build();
            mergeMtcAnchor(built);
            loadedAnchors++;
            loadedSubtrees += built.getSubtrees().size();
            loadedBatchKeys += built.getBatchKeys().size();
          }
        }

        if (root.has("caId")) {
          MtcTrustAnchor rawAnchor = jsonMapper.treeToValue(root, MtcTrustAnchor.class);
          MtcTrustAnchor.MtcTrustAnchorBuilder b =
              rawAnchor.toBuilder().keyTableAuthenticated(true);
          if (!rawAnchor.getAaguid().isPresent() && statementAaguid != null) {
            b.aaguid(statementAaguid);
          }
          MtcTrustAnchor built = b.build();
          mergeMtcAnchor(built);
          loadedAnchors++;
          loadedSubtrees += built.getSubtrees().size();
          loadedBatchKeys += built.getBatchKeys().size();
        }
      }
    }

    JsonNodeFactory f = JsonNodeFactory.instance;
    ObjectNode result = f.objectNode();
    result.put("success", true);
    result.put("loadedMtcAnchors", loadedAnchors);
    result.put("loadedSubtrees", loadedSubtrees);
    result.put("loadedBatchKeys", loadedBatchKeys);
    result.put("loadedX509Certs", loadedX509Certs);
    result.set("metadata", getMetadataSummary());
    return result;
  }

  public ObjectNode getMetadataSummary() {
    JsonNodeFactory f = JsonNodeFactory.instance;
    ObjectNode summary = f.objectNode();
    ArrayNode anchorsArray = f.arrayNode();
    ArrayNode certsArray = f.arrayNode();

    synchronized (activeMtcAnchors) {
      for (MtcTrustAnchor anchor : activeMtcAnchors.values()) {
        ObjectNode aNode = f.objectNode();
        aNode.put("caId", anchor.getCaId().getBase64Url());
        aNode.put("caIdHex", anchor.getCaId().getHex());
        anchor.getAaguid().ifPresent(a -> aNode.put("aaguid", a.getHex()));
        anchor.getLogNumber().ifPresent(ln -> aNode.put("logNumber", ln));
        aNode.put("subtreesCount", anchor.getSubtrees().size());
        ArrayNode stArray = f.arrayNode();
        for (MtcSubtree st : anchor.getSubtrees()) {
          ObjectNode stNode = f.objectNode();
          st.getLogNumber().ifPresent(ln -> stNode.put("logNumber", ln));
          stNode.put("start", st.getStart());
          stNode.put("end", st.getEnd());
          stNode.put("rootHash", st.getRootHash().getBase64Url());
          stArray.add(stNode);
        }
        aNode.set("subtrees", stArray);

        aNode.put("batchKeysCount", anchor.getBatchKeys().size());
        ArrayNode bkArray = f.arrayNode();
        for (MtcBatchKeyEntry bk : anchor.getBatchKeys()) {
          ObjectNode bkNode = f.objectNode();
          bkNode.put("serial", bk.getSerial());
          bk.getAlg().ifPresent(alg -> bkNode.put("alg", alg));
          bk.getDeviceSerial().ifPresent(ds -> bkNode.put("deviceSerial", ds));
          bk.getNotBefore().ifPresent(nb -> bkNode.put("notBefore", nb));
          bk.getNotAfter().ifPresent(na -> bkNode.put("notAfter", na));
          bk.getFirmwareVersion().ifPresent(fw -> bkNode.put("firmwareVersion", fw));
          bkArray.add(bkNode);
        }
        aNode.set("batchKeys", bkArray);
        anchorsArray.add(aNode);
      }

      for (X509Certificate cert : dynamicX509TrustRoots) {
        ObjectNode cNode = f.objectNode();
        cNode.put("subject", cert.getSubjectX500Principal().getName());
        cNode.put("alg", cert.getSigAlgName());
        certsArray.add(cNode);
      }
    }

    summary.set("mtcTrustAnchors", anchorsArray);
    summary.set("x509TrustRoots", certsArray);
    return summary;
  }

  private static ByteArray generateRandom(int length) {
    byte[] bytes = new byte[length];
    random.nextBytes(bytes);
    return new ByteArray(bytes);
  }

  private static <K, V> Cache<K, V> newCache() {
    return CacheBuilder.newBuilder()
        .maximumSize(100)
        .expireAfterAccess(10, TimeUnit.MINUTES)
        .build();
  }

  public Either<String, RegistrationRequest> startRegistration(
      @NonNull String username,
      @NonNull String displayName,
      Optional<String> credentialNickname,
      ResidentKeyRequirement residentKeyRequirement,
      Optional<ByteArray> sessionToken)
      throws ExecutionException {
    return startRegistration(
        username,
        displayName,
        credentialNickname,
        residentKeyRequirement,
        sessionToken,
        Optional.empty(),
        Optional.empty(),
        false);
  }

  public Either<String, RegistrationRequest> startRegistration(
      @NonNull String username,
      @NonNull String displayName,
      Optional<String> credentialNickname,
      ResidentKeyRequirement residentKeyRequirement,
      Optional<ByteArray> sessionToken,
      Optional<AttestationConveyancePreference> attestation,
      Optional<List<String>> attestationFormats,
      boolean mtcDebug)
      throws ExecutionException {
    return startRegistration(
        username,
        displayName,
        credentialNickname,
        residentKeyRequirement,
        sessionToken,
        attestation,
        attestationFormats,
        mtcDebug,
        Optional.empty());
  }

  public Either<String, RegistrationRequest> startRegistration(
      @NonNull String username,
      @NonNull String displayName,
      Optional<String> credentialNickname,
      ResidentKeyRequirement residentKeyRequirement,
      Optional<ByteArray> sessionToken,
      Optional<AttestationConveyancePreference> attestation,
      Optional<List<String>> attestationFormats,
      boolean mtcDebug,
      Optional<List<PublicKeyCredentialParameters>> pubKeyCredParams)
      throws ExecutionException {
    logger.trace(
        "startRegistration username: {}, credentialNickname: {}, attestation: {}, attestationFormats: {}, mtcDebug: {}, pubKeyCredParams: {}",
        username,
        credentialNickname,
        attestation,
        attestationFormats,
        mtcDebug,
        pubKeyCredParams);

    final Collection<CredentialRegistration> registrations =
        userStorage.getRegistrationsByUsername(username);
    final Optional<UserIdentity> existingUser =
        registrations.stream().findAny().map(CredentialRegistration::getUserIdentity);
    final boolean permissionGranted =
        existingUser
            .map(userIdentity -> sessions.isSessionForUser(userIdentity.getId(), sessionToken))
            .orElse(true);

    if (permissionGranted) {
      final UserIdentity registrationUserId =
          existingUser.orElseGet(
              () ->
                  UserIdentity.builder()
                      .name(username)
                      .displayName(displayName)
                      .id(generateRandom(32))
                      .build());

      StartRegistrationOptions.StartRegistrationOptionsBuilder optionsBuilder =
          StartRegistrationOptions.builder()
              .user(registrationUserId)
              .authenticatorSelection(
                  AuthenticatorSelectionCriteria.builder()
                      .residentKey(residentKeyRequirement)
                      .build())
              .attestation(attestation)
              .attestationFormats(attestationFormats)
              .pubKeyCredParams(pubKeyCredParams);

      if (mtcDebug) {
        optionsBuilder.extensions(RegistrationExtensionInputs.builder().mtcDebug(true).build());
      }

      RegistrationRequest request =
          new RegistrationRequest(
              username,
              credentialNickname,
              generateRandom(32),
              rp.startRegistration(optionsBuilder.build()),
              Optional.of(sessions.createSession(registrationUserId.getId())));
      registerRequestStorage.put(request.getRequestId(), request);
      return Either.right(request);
    } else {
      return Either.left("The username \"" + username + "\" is already registered.");
    }
  }

  @Value
  public static class SuccessfulRegistrationResult {
    final boolean success = true;
    RegistrationRequest request;
    RegistrationResponse response;
    CredentialRegistration registration;
    boolean attestationTrusted;
    AttestationType attestationType;
    Optional<MtcAttestationInfo> mtcAttestation;
    Optional<AttestationCertInfo> attestationCert;
    List<String> debugLog;

    @JsonSerialize(using = AuthDataSerializer.class)
    AuthenticatorData authData;

    String username;
    ByteArray sessionToken;

    public SuccessfulRegistrationResult(
        RegistrationRequest request,
        RegistrationResponse response,
        CredentialRegistration registration,
        boolean attestationTrusted,
        AttestationType attestationType,
        Optional<MtcAttestationInfo> mtcAttestation,
        List<String> debugLog,
        ByteArray sessionToken) {
      this.request = request;
      this.response = response;
      this.registration = registration;
      this.attestationTrusted = attestationTrusted;
      this.attestationType = attestationType;
      this.mtcAttestation = mtcAttestation;
      this.debugLog = debugLog;
      attestationCert =
          Optional.ofNullable(
                  response
                      .getCredential()
                      .getResponse()
                      .getAttestation()
                      .getAttestationStatement()
                      .get("x5c"))
              .map(certs -> certs.get(0))
              .flatMap(
                  (JsonNode certDer) -> {
                    try {
                      return Optional.of(new ByteArray(certDer.binaryValue()));
                    } catch (IOException e) {
                      logger.error("Failed to get binary value from x5c element: {}", certDer, e);
                      return Optional.empty();
                    }
                  })
              .map(AttestationCertInfo::new);
      this.authData = response.getCredential().getResponse().getParsedAuthenticatorData();
      this.username = request.getUsername();
      this.sessionToken = sessionToken;
    }
  }

  @Value
  public static class AttestationCertInfo {
    final ByteArray der;
    final String text;

    public AttestationCertInfo(ByteArray certDer) {
      der = certDer;
      X509Certificate cert = null;
      try {
        cert = CertificateParser.parseDer(certDer.getBytes());
      } catch (CertificateException e) {
        logger.error("Failed to parse attestation certificate");
      }
      if (cert == null) {
        text = null;
      } else {
        text = cert.toString();
      }
    }
  }

  private void appendMakeCredentialPreDebugLog(
      RegistrationRequest request, RegistrationResponse response, List<String> debugLog) {
    try {
      debugLog.add(
          String.format(
              "[Step 1] Received MakeCredential response | requestId=%s | username=\"%s\"",
              response.getRequestId().getBase64Url(), request.getUsername()));
      ByteArray credId = response.getCredential().getId();
      debugLog.add(
          String.format(
              "  • Credential ID: %s (%d bytes)",
              credId.getBase64Url(), credId.getBytes().length));
      debugLog.add(
          String.format(
              "  • ClientDataJSON: type=\"%s\" | origin=\"%s\" | challenge=%s",
              response.getCredential().getResponse().getClientData().getType(),
              response.getCredential().getResponse().getClientData().getOrigin(),
              response.getCredential().getResponse().getClientData().getChallenge().getBase64Url()));

      AuthenticatorData authData =
          response.getCredential().getResponse().getParsedAuthenticatorData();
      debugLog.add(
          String.format(
              "[Step 2] Parsed AuthenticatorData | rpIdHash=%s | signCount=%d",
              authData.getRpIdHash().getHex(), authData.getSignatureCounter()));
      debugLog.add(
          String.format(
              "  • Flags: UP=%s, UV=%s, AT=%s, ED=%s, BE=%s, BS=%s",
              authData.getFlags().UP,
              authData.getFlags().UV,
              authData.getFlags().AT,
              authData.getFlags().ED,
              authData.getFlags().BE,
              authData.getFlags().BS));
      authData
          .getAttestedCredentialData()
          .ifPresent(
              acd -> {
                ByteArray pubKeyCbor = acd.getCredentialPublicKey();
                String algDesc = "unknown";
                try {
                  com.upokecenter.cbor.CBORObject cose =
                      com.upokecenter.cbor.CBORObject.DecodeFromBytes(pubKeyCbor.getBytes());
                  if (cose != null && cose.ContainsKey(com.upokecenter.cbor.CBORObject.FromObject(3))) {
                    int algId = cose.get(com.upokecenter.cbor.CBORObject.FromObject(3)).AsInt32();
                    algDesc =
                        String.valueOf(algId)
                            + COSEAlgorithmIdentifier.fromId(algId)
                                .map(a -> " (" + a.name() + ")")
                                .orElse("");
                  }
                } catch (Exception ignored) {
                }
                debugLog.add(
                    String.format(
                        "  • AttestedCredentialData: aaguid=%s | credentialPublicKey alg=%s (%d bytes)",
                        acd.getAaguid().getHex(), algDesc, pubKeyCbor.getBytes().length));
              });

      Optional<com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput>
          clientDebug = response.getCredential().getClientExtensionResults().getMtcDebug();
      Optional<com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput>
          authDataDebug =
              authData
                  .getExtensions()
                  .flatMap(
                      com.yubico.webauthn.data.Extensions.MtcDebug
                          ::parseAuthenticatorExtensionOutput);
      Optional<com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput>
          effectiveDebug = clientDebug.isPresent() ? clientDebug : authDataDebug;
      if (effectiveDebug.isPresent()) {
        com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput dbg =
            effectiveDebug.get();
        debugLog.add(
            String.format(
                "[Step 3] mtc-debug Extension Present (clientExt=%s, authDataExt=%s)",
                clientDebug.isPresent(), authDataDebug.isPresent()));
        debugLog.add(
            String.format(
                "  • pubKey=%s | deviceSerial=%s | notBefore=%s | notAfter=%s | firmwareVersion=%s | mtcProof=%s | rootHash=%s",
                dbg.getPubKey() != null ? dbg.getPubKey().getBytes().length + "B" : "absent",
                dbg.getDeviceSerial().map(s -> "\"" + s + "\"").orElse("absent"),
                dbg.getNotBefore().map(String::valueOf).orElse("absent"),
                dbg.getNotAfter().map(String::valueOf).orElse("absent"),
                dbg.getFirmwareVersion()
                    .map(fw -> String.format("%d (0x%08x)", fw, fw))
                    .orElse("absent"),
                dbg.getMtcProof().map(b -> b.getBytes().length + "B").orElse("absent"),
                dbg.getRootHash().map(ByteArray::getBase64Url).orElse("absent")));
      } else {
        debugLog.add("[Step 3] mtc-debug Extension: not present in response");
      }

      String fmt = response.getCredential().getResponse().getAttestation().getFormat();
      int attObjSize =
          response.getCredential().getResponse().getAttestationObject().getBytes().length;
      ObjectNode attStmt =
          response.getCredential().getResponse().getAttestation().getAttestationStatement();
      debugLog.add(
          String.format(
              "[Step 4] AttestationObject: fmt=\"%s\" | total CBOR size=%d bytes",
              fmt, attObjSize));

      if ("mtc".equals(fmt)) {
        long alg = attStmt.path("alg").asLong(0);
        int sigLen =
            attStmt.has("sig") && attStmt.get("sig").isBinary()
                ? getBinaryLength(attStmt.get("sig"))
                : 0;
        JsonNode mtcCert = attStmt.path("mtcCert");
        boolean isEntryDesc = mtcCert.has("mtcProof");
        ByteArray caId =
            mtcCert.has("caId") && mtcCert.get("caId").isBinary()
                ? new ByteArray(mtcCert.get("caId").binaryValue())
                : new ByteArray(new byte[0]);
        long serial = mtcCert.path("serial").asLong(0);
        int logNumber = (int) (serial >>> 48);
        long leafIndex = serial & 0xFFFFFFFFFFFFL;
        debugLog.add(
            String.format(
                "  • fmt=\"mtc\" statement: alg=%d | sig=%d bytes | mtcCert form=%s",
                alg, sigLen, isEntryDesc ? "mtcEntryDesc (with mtcProof)" : "mtcKeyRef (proof-less)"));
        debugLog.add(
            String.format(
                "  • caId=%s (hex=%s) | serial=%d (logNumber=%d, leafIndex=%d)",
                caId.getBase64Url(), caId.getHex(), serial, logNumber, leafIndex));
        Optional<ByteArray> aaguidOpt =
            authData
                .getAttestedCredentialData()
                .map(com.yubico.webauthn.data.AttestedCredentialData::getAaguid);
        Optional<MtcTrustAnchor> anchorOpt = mtcTrustSource.findMtcTrustAnchor(caId, aaguidOpt);
        if (anchorOpt.isPresent()) {
          MtcTrustAnchor anchor = anchorOpt.get();
          Optional<MtcBatchKeyEntry> bkOpt = anchor.findBatchKey(serial);
          debugLog.add(
              String.format(
                  "  • MtcTrustSource Lookup: FOUND anchor for caId=%s (subtrees=%d, batchKeys=%d) | batchKey for serial %d: %s",
                  caId.getBase64Url(),
                  anchor.getSubtrees().size(),
                  anchor.getBatchKeys().size(),
                  serial,
                  bkOpt.isPresent()
                      ? "FOUND in metadata/manifest"
                      : "NOT in metadata/manifest (requires mtc-debug.pubKey)"));
        } else {
          debugLog.add(
              String.format(
                  "  • MtcTrustSource Lookup: NO anchor loaded for caId=%s (will use mtc-debug diagnostic verification if present)",
                  caId.getBase64Url()));
        }
      } else if (attStmt.has("x5c") && attStmt.get("x5c").isArray() && attStmt.get("x5c").size() > 0) {
        long alg = attStmt.path("alg").asLong(0);
        int sigLen = getBinaryLength(attStmt.get("sig"));
        debugLog.add(
            String.format(
                "  • X.509 statement: alg=%d | sig=%d bytes | x5c chain length=%d",
                alg, sigLen, attStmt.get("x5c").size()));
      }
    } catch (Exception e) {
      debugLog.add("  • [Warning] Pre-validation inspection encountered: " + e.getMessage());
    }
  }

  private static int getBinaryLength(JsonNode node) {
    try {
      return node != null && node.isBinary() ? node.binaryValue().length : 0;
    } catch (IOException e) {
      return 0;
    }
  }

  public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(
      String responseJson) {
    logger.trace("finishRegistration responseJson: {}", responseJson);
    List<String> debugLog = new ArrayList<>();
    RegistrationResponse response = null;
    try {
      response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
    } catch (IOException e) {
      logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
      debugLog.add("[RESULT: FAILURE] Failed to decode RegistrationResponse JSON: " + e.getMessage());
      return Either.left(debugLog);
    }

    RegistrationRequest request = registerRequestStorage.getIfPresent(response.getRequestId());
    registerRequestStorage.invalidate(response.getRequestId());

    if (request == null) {
      logger.debug("fail finishRegistration responseJson: {}", responseJson);
      debugLog.add("[RESULT: FAILURE] No active registration request found for requestId.");
      return Either.left(debugLog);
    } else {
      appendMakeCredentialPreDebugLog(request, response, debugLog);
      try {
        com.yubico.webauthn.RegistrationResult registration =
            rp.finishRegistration(
                FinishRegistrationOptions.builder()
                    .request(request.getPublicKeyCredentialCreationOptions())
                    .response(response.getCredential())
                    .build());

        if (userStorage.userExists(request.getUsername())) {
          boolean permissionGranted = false;

          final boolean isValidSession =
              request
                  .getSessionToken()
                  .map(
                      token ->
                          sessions.isSessionForUser(
                              request.getPublicKeyCredentialCreationOptions().getUser().getId(),
                              token))
                  .orElse(false);

          logger.debug("Session token: {}", request.getSessionToken());
          logger.debug("Valid session: {}", isValidSession);

          if (isValidSession) {
            permissionGranted = true;
            logger.info(
                "Session token accepted for user {}",
                request.getPublicKeyCredentialCreationOptions().getUser().getId());
          }

          logger.debug("permissionGranted: {}", permissionGranted);

          if (!permissionGranted) {
            throw new RegistrationFailedException(
                new IllegalArgumentException(
                    String.format("User %s already exists", request.getUsername())));
          }
        }

        registration
            .getMtcAttestation()
            .ifPresent(
                mtc -> {
                  debugLog.add(
                      String.format(
                          "[Step 5] MTC Verification Complete | keySource=%s | rootHash=%s",
                          mtc.getKeySource(),
                          mtc.getSubtreeRootHash().map(ByteArray::getBase64Url).orElse("none")));
                  debugLog.add(
                      String.format(
                          "  • enterprise=%s | deviceSerial=%s | firmwareVersion=%s | validity=[%s .. %s]",
                          mtc.isEnterprise(),
                          mtc.getDeviceSerial().map(s -> "\"" + s + "\"").orElse("none"),
                          mtc.getFirmwareVersion()
                              .map(fw -> String.format("%d (0x%08x)", fw, fw))
                              .orElse("none"),
                          mtc.getNotBefore().map(String::valueOf).orElse("none"),
                          mtc.getNotAfter().map(String::valueOf).orElse("none")));
                });
        debugLog.add(
            String.format(
                "[RESULT: SUCCESS] MakeCredential validation PASSED | attestationType=%s | attestationTrusted=%s",
                registration.getAttestationType(), registration.isAttestationTrusted()));

        return Either.right(
            new SuccessfulRegistrationResult(
                request,
                response,
                addRegistration(
                    request.getPublicKeyCredentialCreationOptions().getUser(),
                    request.getCredentialNickname(),
                    registration),
                registration.isAttestationTrusted(),
                registration.getAttestationType(),
                registration.getMtcAttestation(),
                debugLog,
                sessions.createSession(
                    request.getPublicKeyCredentialCreationOptions().getUser().getId())));
      } catch (RegistrationFailedException e) {
        logger.debug("fail finishRegistration responseJson: {}", responseJson, e);
        appendFailureCauseChain(e, debugLog);
        return Either.left(debugLog);
      } catch (Exception e) {
        logger.error("fail finishRegistration responseJson: {}", responseJson, e);
        appendFailureCauseChain(e, debugLog);
        return Either.left(debugLog);
      }
    }
  }

  private static void appendFailureCauseChain(Throwable e, List<String> debugLog) {
    debugLog.add("[Step 5] Cryptographic / Ceremony Verification Failed:");
    Throwable cur = e;
    int depth = 0;
    while (cur != null && depth < 6) {
      debugLog.add(
          String.format("  • [%s] %s", cur.getClass().getSimpleName(), cur.getMessage()));
      cur = cur.getCause();
      depth++;
    }
    debugLog.add("[RESULT: FAILURE] MakeCredential validation FAILED: " + e.getMessage());
  }

  /**
   * Generates a simulated {@code fmt: "mtc"} WebAuthn registration credential for the given mode
   * ({@code "batch-mds"}, {@code "enterprise-manifest"}, or {@code "enterprise-mtc-debug"}) and
   * active {@code requestId}.
   */
  public Either<List<String>, RegistrationResponse> createSimulatedMtcRegistrationResponse(
      @NonNull ByteArray requestId, @NonNull String mode, @NonNull String origin) {
    RegistrationRequest request = registerRequestStorage.getIfPresent(requestId);
    if (request == null) {
      return Either.left(
          Arrays.asList("Simulation failed!", "No such registration request in progress."));
    }

    try {
      boolean allowsEs256 =
          request.getPublicKeyCredentialCreationOptions().getPubKeyCredParams().stream()
              .anyMatch(p -> p.getAlg() == COSEAlgorithmIdentifier.ES256);
      boolean allowsMlDsa44 =
          request.getPublicKeyCredentialCreationOptions().getPubKeyCredParams().stream()
              .anyMatch(p -> p.getAlg() == COSEAlgorithmIdentifier.ML_DSA_44);
      final ByteArray credCoseKey;
      if (!allowsEs256 && allowsMlDsa44) {
        credCoseKey = ByteArray.fromBase64Url(FIDONT_ENTERPRISE_COSE_KEY_B64);
      } else {
        KeyPairGenerator credKpg = KeyPairGenerator.getInstance("EC");
        credKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair credKeyPair = credKpg.generateKeyPair();
        credCoseKey = ecPublicKeyToCose((ECPublicKey) credKeyPair.getPublic());
      }
      ByteArray credentialId = generateRandom(32);

      // Build authenticatorData
      byte[] rpIdHash =
          MessageDigest.getInstance("SHA-256")
              .digest(
                  request
                      .getPublicKeyCredentialCreationOptions()
                      .getRp()
                      .getId()
                      .getBytes(StandardCharsets.UTF_8));
      boolean includeMtcDebug =
          "enterprise-mtc-debug".equalsIgnoreCase(mode)
              || "enterprise-keyref-mtc-debug".equalsIgnoreCase(mode);
      boolean useKeyRef = "enterprise-keyref-mtc-debug".equalsIgnoreCase(mode);
      byte flags = (byte) (0x01 | 0x04 | 0x40 | (includeMtcDebug ? 0x80 : 0x00)); // UP | UV | AT | ED?

      byte[] extBytes = new byte[0];
      com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput clientMtcDebug = null;
      if (includeMtcDebug) {
        ByteArray enterpriseCoseKey = ByteArray.fromBase64Url(FIDONT_ENTERPRISE_COSE_KEY_B64);
        ByteArray enterpriseProof = ByteArray.fromBase64Url(FIDONT_ENTERPRISE_MTC_PROOF_B64);
        ByteArray enterpriseRootHash = ByteArray.fromBase64Url(FIDONT_ENTERPRISE_ROOT_HASH_B64);
        com.upokecenter.cbor.CBORObject mtcDebugMap = com.upokecenter.cbor.CBORObject.NewOrderedMap();
        mtcDebugMap.Add("pubKey", enterpriseCoseKey.getBytes());
        mtcDebugMap.Add("deviceSerial", DEMO_DEVICE_SERIAL);
        mtcDebugMap.Add("notBefore", DEMO_NOT_BEFORE);
        mtcDebugMap.Add("notAfter", DEMO_NOT_AFTER);
        mtcDebugMap.Add("mtcProof", enterpriseProof.getBytes());
        mtcDebugMap.Add("rootHash", enterpriseRootHash.getBytes());
        com.upokecenter.cbor.CBORObject exts = com.upokecenter.cbor.CBORObject.NewOrderedMap();
        exts.Add("mtc-debug", mtcDebugMap);
        extBytes =
            exts.EncodeToBytes(com.upokecenter.cbor.CBOREncodeOptions.DefaultCtap2Canonical);
        clientMtcDebug =
            com.yubico.webauthn.data.Extensions.MtcDebug.MtcDebugRegistrationOutput.builder()
                .pubKey(enterpriseCoseKey)
                .deviceSerial(DEMO_DEVICE_SERIAL)
                .notBefore(DEMO_NOT_BEFORE)
                .notAfter(DEMO_NOT_AFTER)
                .mtcProof(enterpriseProof)
                .rootHash(enterpriseRootHash)
                .build();
      }

      byte[] aaguidBytes = FIDONT_AAGUID.getBytes();
      byte[] credIdBytes = credentialId.getBytes();
      byte[] credKeyBytes = credCoseKey.getBytes();
      ByteBuffer authDataBuf =
          ByteBuffer.allocate(
              32 + 1 + 4 + 16 + 2 + credIdBytes.length + credKeyBytes.length + extBytes.length);
      authDataBuf.put(rpIdHash);
      authDataBuf.put(flags);
      authDataBuf.putInt(1); // signCount = 1
      authDataBuf.put(aaguidBytes);
      authDataBuf.putShort((short) credIdBytes.length);
      authDataBuf.put(credIdBytes);
      authDataBuf.put(credKeyBytes);
      authDataBuf.put(extBytes);
      byte[] authDataBytes = authDataBuf.array();

      String clientDataJsonStr =
          String.format(
              "{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"%s\",\"crossOrigin\":false}",
              request.getPublicKeyCredentialCreationOptions().getChallenge().getBase64Url(),
              origin);
      byte[] clientDataBytes = clientDataJsonStr.getBytes(StandardCharsets.UTF_8);
      byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataBytes);

      byte[] signedData = new byte[authDataBytes.length + clientDataHash.length];
      System.arraycopy(authDataBytes, 0, signedData, 0, authDataBytes.length);
      System.arraycopy(clientDataHash, 0, signedData, authDataBytes.length, clientDataHash.length);

      final int alg;
      final byte[] sigBytes;
      final byte[] caIdBytes;
      final byte[] mtcProofBytes;

      if ("batch-mds".equalsIgnoreCase(mode)) {
        alg = -7; // ES256
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(DEMO_BATCH_KEYPAIR.getPrivate());
        ecdsa.update(signedData);
        sigBytes = ecdsa.sign();
        caIdBytes = DEMO_BATCH_CA_ID.getBytes();
        // Single-leaf MTCProof: ext_len(0) || start(0) || end(1) || proof_len(0) || sig_len(0)
        ByteBuffer proofBuf = ByteBuffer.allocate(2 + 6 + 6 + 2 + 3);
        proofBuf.putShort((short) 0);
        proofBuf.put(new byte[6]);
        proofBuf.put(new byte[] {0, 0, 0, 0, 0, 1});
        proofBuf.putShort((short) 0);
        proofBuf.put(new byte[] {0, 0, 0});
        mtcProofBytes = proofBuf.array();
      } else {
        alg = -48; // ML-DSA-44
        byte[] pkcs8 = Base64.getDecoder().decode(FIDONT_ENTERPRISE_PKCS8_B64);
        PrivateKey mlDsaKey =
            KeyFactory.getInstance("ML-DSA-44", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Signature mlDsa = Signature.getInstance("ML-DSA-44", "BC");
        mlDsa.initSign(mlDsaKey);
        mlDsa.update(signedData);
        sigBytes = mlDsa.sign();
        if ("enterprise-manifest".equalsIgnoreCase(mode)) {
          caIdBytes = ENTERPRISE_MANIFEST_CA_ID.getBytes();
          byte[] serialUtf8 = DEMO_DEVICE_SERIAL.getBytes(StandardCharsets.UTF_8);
          ByteBuffer proofBuf = ByteBuffer.allocate(2 + serialUtf8.length + 6 + 6 + 2 + 3);
          proofBuf.putShort((short) serialUtf8.length);
          proofBuf.put(serialUtf8);
          proofBuf.put(new byte[6]);
          proofBuf.put(new byte[] {0, 0, 0, 0, 0, 1});
          proofBuf.putShort((short) 0);
          proofBuf.put(new byte[] {0, 0, 0});
          mtcProofBytes = proofBuf.array();
        } else {
          caIdBytes = ENTERPRISE_CA_ID.getBytes();
          mtcProofBytes = ByteArray.fromBase64Url(FIDONT_ENTERPRISE_MTC_PROOF_B64).getBytes();
        }
      }

      // Build consolidated fmt="mtc" attestationObject (NO inline pubKey in attStmt)
      com.upokecenter.cbor.CBORObject mtcCert = com.upokecenter.cbor.CBORObject.NewOrderedMap();
      mtcCert.Add("caId", caIdBytes);
      mtcCert.Add("serial", DEMO_SERIAL);
      if (!useKeyRef) {
        mtcCert.Add("notBefore", DEMO_NOT_BEFORE);
        mtcCert.Add("notAfter", DEMO_NOT_AFTER);
        mtcCert.Add("mtcProof", mtcProofBytes);
      }

      com.upokecenter.cbor.CBORObject attStmt = com.upokecenter.cbor.CBORObject.NewOrderedMap();
      attStmt.Add("alg", alg);
      attStmt.Add("sig", sigBytes);
      attStmt.Add("mtcCert", mtcCert);

      com.upokecenter.cbor.CBORObject attObj = com.upokecenter.cbor.CBORObject.NewOrderedMap();
      attObj.Add("fmt", "mtc");
      attObj.Add("authData", authDataBytes);
      attObj.Add("attStmt", attStmt);

      ByteArray attestationObjectBytes = new ByteArray(attObj.EncodeToBytes());

      AuthenticatorAttestationResponse attResp =
          AuthenticatorAttestationResponse.builder()
              .attestationObject(attestationObjectBytes)
              .clientDataJSON(new ByteArray(clientDataBytes))
              .build();

      ClientRegistrationExtensionOutputs.ClientRegistrationExtensionOutputsBuilder clientExtsBuilder =
          ClientRegistrationExtensionOutputs.builder();
      if (clientMtcDebug != null) {
        clientExtsBuilder.mtcDebug(clientMtcDebug);
      }

      PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
          credential =
              PublicKeyCredential
                  .<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                  .id(credentialId)
                  .response(attResp)
                  .clientExtensionResults(clientExtsBuilder.build())
                  .build();

      return Either.right(
          new RegistrationResponse(request.getRequestId(), credential, request.getSessionToken()));
    } catch (Exception e) {
      logger.error("Failed to simulate MTC registration", e);
      return Either.left(Arrays.asList("MTC simulation failed!", e.getMessage()));
    }
  }

  public Either<List<String>, AssertionRequestWrapper> startAuthentication(
      Optional<String> username) {
    logger.trace("startAuthentication username: {}", username);

    if (username.isPresent() && !userStorage.userExists(username.get())) {
      return Either.left(
          Collections.singletonList("The username \"" + username.get() + "\" is not registered."));
    } else {
      AssertionRequestWrapper request =
          new AssertionRequestWrapper(
              generateRandom(32),
              rp.startAssertion(StartAssertionOptions.builder().username(username).build()));

      assertRequestStorage.put(request.getRequestId(), request);

      return Either.right(request);
    }
  }

  @Value
  @AllArgsConstructor
  public static final class SuccessfulAuthenticationResult {
    private final boolean success = true;
    private final AssertionRequestWrapper request;
    private final AssertionResponse response;
    private final Collection<CredentialRegistration> registrations;

    @JsonSerialize(using = AuthDataSerializer.class)
    AuthenticatorData authData;

    private final String username;
    private final ByteArray sessionToken;

    public SuccessfulAuthenticationResult(
        AssertionRequestWrapper request,
        AssertionResponse response,
        Collection<CredentialRegistration> registrations,
        String username,
        ByteArray sessionToken) {
      this(
          request,
          response,
          registrations,
          response.getCredential().getResponse().getParsedAuthenticatorData(),
          username,
          sessionToken);
    }
  }

  public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(
      String responseJson) {
    logger.trace("finishAuthentication responseJson: {}", responseJson);

    final AssertionResponse response;
    try {
      response = jsonMapper.readValue(responseJson, AssertionResponse.class);
    } catch (IOException e) {
      logger.debug("Failed to decode response object", e);
      return Either.left(
          Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
    }

    AssertionRequestWrapper request = assertRequestStorage.getIfPresent(response.getRequestId());
    assertRequestStorage.invalidate(response.getRequestId());

    if (request == null) {
      return Either.left(Arrays.asList("Assertion failed!", "No such assertion in progress."));
    } else {
      try {
        AssertionResultV2<CredentialRegistration> result =
            rp.finishAssertion(
                FinishAssertionOptions.builder()
                    .request(request.getRequest())
                    .response(response.getCredential())
                    .build());

        if (result.isSuccess()) {
          try {
            userStorage.updateSignatureCount(result);
          } catch (Exception e) {
            logger.error(
                "Failed to update signature count for user \"{}\", credential \"{}\"",
                result.getCredential().getUsername(),
                response.getCredential().getId(),
                e);
          }

          return Either.right(
              new SuccessfulAuthenticationResult(
                  request,
                  response,
                  userStorage.getRegistrationsByUsername(result.getCredential().getUsername()),
                  result.getCredential().getUsername(),
                  sessions.createSession(result.getCredential().getUserHandle())));
        } else {
          return Either.left(Collections.singletonList("Assertion failed: Invalid assertion."));
        }
      } catch (AssertionFailedException e) {
        logger.debug("Assertion failed", e);
        return Either.left(Arrays.asList("Assertion failed!", e.getMessage()));
      } catch (Exception e) {
        logger.error("Assertion failed", e);
        return Either.left(
            Arrays.asList("Assertion failed unexpectedly; this is likely a bug.", e.getMessage()));
      }
    }
  }

  @Value
  public static final class DeregisterCredentialResult {
    boolean success = true;
    CredentialRegistration droppedRegistration;
    boolean accountDeleted;
  }

  public Either<List<String>, DeregisterCredentialResult> deregisterCredential(
      @NonNull ByteArray sessionToken, ByteArray credentialId) {
    logger.trace("deregisterCredential session: {}, credentialId: {}", sessionToken, credentialId);

    if (credentialId == null || credentialId.getBytes().length == 0) {
      return Either.left(Collections.singletonList("Credential ID must not be empty."));
    }

    Optional<ByteArray> session = sessions.getSession(sessionToken);
    if (session.isPresent()) {
      ByteArray userHandle = session.get();
      Optional<String> username = userStorage.getUsernameForUserHandle(userHandle);

      if (username.isPresent()) {
        Optional<CredentialRegistration> credReg =
            userStorage.getRegistrationByUsernameAndCredentialId(username.get(), credentialId);
        if (credReg.isPresent()) {
          userStorage.removeRegistrationByUsername(username.get(), credReg.get());

          return Either.right(
              new DeregisterCredentialResult(
                  credReg.get(), !userStorage.userExists(username.get())));
        } else {
          return Either.left(
              Collections.singletonList("Credential ID not registered:" + credentialId));
        }
      } else {
        return Either.left(Collections.singletonList("Invalid user handle"));
      }
    } else {
      return Either.left(Collections.singletonList("Invalid session"));
    }
  }

  public <T> Either<List<String>, T> deleteAccount(String username, Supplier<T> onSuccess) {
    logger.trace("deleteAccount username: {}", username);

    if (username == null || username.isEmpty()) {
      return Either.left(Collections.singletonList("Username must not be empty."));
    }

    boolean removed = userStorage.removeAllRegistrations(username);

    if (removed) {
      return Either.right(onSuccess.get());
    } else {
      return Either.left(Collections.singletonList("Username not registered:" + username));
    }
  }

  private CredentialRegistration addRegistration(
      UserIdentity userIdentity, Optional<String> nickname, RegistrationResult result) {
    return addRegistration(
        userIdentity,
        nickname,
        RegisteredCredential.builder()
            .credentialId(result.getKeyId().getId())
            .userHandle(userIdentity.getId())
            .publicKeyCose(result.getPublicKeyCose())
            .signatureCount(result.getSignatureCount())
            .build(),
        result.getKeyId().getTransports().orElseGet(TreeSet::new),
        metadataService.findEntries(result).stream().findAny());
  }

  private CredentialRegistration addRegistration(
      UserIdentity userIdentity,
      Optional<String> nickname,
      RegisteredCredential credential,
      SortedSet<AuthenticatorTransport> transports,
      Optional<Object> attestationMetadata) {
    CredentialRegistration reg =
        CredentialRegistration.builder()
            .userIdentity(userIdentity)
            .credentialNickname(nickname)
            .registrationTime(clock.instant())
            .credential(credential)
            .transports(transports)
            .attestationMetadata(attestationMetadata)
            .build();

    logger.debug(
        "Adding registration: user: {}, nickname: {}, credential: {}",
        userIdentity,
        nickname,
        credential);
    userStorage.addRegistrationByUsername(userIdentity.getName(), reg);
    return reg;
  }

  private static class AuthDataSerializer extends JsonSerializer<AuthenticatorData> {
    @Override
    public void serialize(
        AuthenticatorData value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      gen.writeStartObject();
      gen.writeStringField("rpIdHash", value.getRpIdHash().getHex());
      gen.writeObjectField("flags", value.getFlags());
      gen.writeNumberField("signatureCounter", value.getSignatureCounter());
      value
          .getAttestedCredentialData()
          .ifPresent(
              acd -> {
                try {
                  gen.writeObjectFieldStart("attestedCredentialData");
                  gen.writeStringField("aaguid", acd.getAaguid().getHex());
                  gen.writeStringField("credentialId", acd.getCredentialId().getHex());
                  gen.writeStringField("publicKey", acd.getCredentialPublicKey().getHex());
                  gen.writeEndObject();
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });
      value
          .getExtensions()
          .ifPresent(
              extensions -> {
                try {
                  gen.writeObjectField(
                      "extensions", JacksonCodecs.cbor().readTree(extensions.EncodeToBytes()));
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });
      gen.writeEndObject();
    }
  }
}
