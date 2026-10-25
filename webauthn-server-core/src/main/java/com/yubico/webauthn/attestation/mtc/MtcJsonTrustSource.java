package com.yubico.webauthn.attestation.mtc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.HexException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * An {@link MtcTrustSource} backed by one or more {@link MtcTrustAnchor} entries loaded from FIDO
 * MDS3 {@code MetadataStatement} JSON documents or enterprise vendor key manifests.
 *
 * <p>When loaded from a {@code MetadataStatement} JSON containing {@code
 * attestationRootCertificates}, every {@link MtcSubtree} checkpoint signature (including RFC 8554
 * {@code HSS-LMS} {@code alg: -46}) is cryptographically verified against {@code
 * attestationRootCertificates} before the subtree root is admitted.
 */
@Slf4j
public class MtcJsonTrustSource implements MtcTrustSource {

  private final Map<ByteArray, List<MtcTrustAnchor>> anchorsByCaId;

  public MtcJsonTrustSource(@NonNull Collection<MtcTrustAnchor> anchors) {
    Map<ByteArray, List<MtcTrustAnchor>> map = new HashMap<>();
    for (MtcTrustAnchor anchor : anchors) {
      map.computeIfAbsent(anchor.getCaId(), k -> new ArrayList<>()).add(anchor);
    }
    this.anchorsByCaId = Collections.unmodifiableMap(map);
  }

  /**
   * Parses a FIDO MDS3 {@code MetadataStatement} JSON string, verifies all {@code
   * FidoMtcSubtreeCheckpoint} signatures against {@code attestationRootCertificates}, and returns
   * an {@link MtcJsonTrustSource}.
   */
  public static MtcJsonTrustSource fromMetadataStatementJson(@NonNull String json)
      throws IOException, CertificateException, HexException {
    ObjectMapper mapper = JacksonCodecs.json();
    return fromMetadataStatementNode(mapper.readTree(json));
  }

  /**
   * Parses a FIDO MDS3 {@code MetadataStatement} JSON stream, verifies all {@code
   * FidoMtcSubtreeCheckpoint} signatures against {@code attestationRootCertificates}, and returns
   * an {@link MtcJsonTrustSource}.
   */
  public static MtcJsonTrustSource fromMetadataStatementStream(@NonNull InputStream in)
      throws IOException, CertificateException, HexException {
    ObjectMapper mapper = JacksonCodecs.json();
    return fromMetadataStatementNode(mapper.readTree(in));
  }

  public static MtcJsonTrustSource fromMetadataStatementNode(@NonNull JsonNode root)
      throws IOException, CertificateException, HexException {
    ObjectMapper mapper = JacksonCodecs.json();

    ByteArray statementAaguid = null;
    JsonNode aaguidNode = root.get("aaguid");
    if (aaguidNode != null && aaguidNode.isTextual()) {
      String hex = aaguidNode.asText().replace("-", "");
      if (hex.length() == 32) {
        statementAaguid = ByteArray.fromHex(hex);
      }
    }

    List<X509Certificate> rootCerts = new ArrayList<>();
    JsonNode certsNode = root.get("attestationRootCertificates");
    if (certsNode != null && certsNode.isArray()) {
      for (JsonNode certText : certsNode) {
        if (certText.isTextual()) {
          rootCerts.add(CertificateParser.parsePem(certText.asText()));
        }
      }
    }

    List<MtcTrustAnchor> verifiedAnchors = new ArrayList<>();
    JsonNode anchorsNode = root.get("mtcTrustAnchors");
    if (anchorsNode != null && anchorsNode.isArray()) {
      for (JsonNode anchorNode : anchorsNode) {
        MtcTrustAnchor rawAnchor = mapper.treeToValue(anchorNode, MtcTrustAnchor.class);
        int defaultLogNumber = rawAnchor.getLogNumber().orElse(0);
        List<MtcSubtree> validSubtrees = new ArrayList<>();
        for (MtcSubtree st : rawAnchor.getSubtrees()) {
          Optional<X509Certificate> matchedCert =
              MtcCheckpoint.findSubtreeSigningCert(
                  rawAnchor.getCaId(), defaultLogNumber, st, rootCerts);
          if (matchedCert.isPresent()) {
            try {
              MtcSubtree resolved =
                  st.getSigningCert().isPresent()
                      ? st
                      : st.toBuilder()
                          .signingCert(new ByteArray(matchedCert.get().getEncoded()))
                          .build();
              validSubtrees.add(resolved);
            } catch (Exception e) {
              validSubtrees.add(st);
            }
          } else {
            log.warn(
                "Rejected MTC subtree [{}, {}) for caId {}: checkpoint signature verification failed.",
                st.getStart(),
                st.getEnd(),
                rawAnchor.getCaId().getBase64Url());
          }
        }

        MtcTrustAnchor.MtcTrustAnchorBuilder b =
            rawAnchor.toBuilder()
                .subtrees(CollectionUtil.immutableList(validSubtrees))
                .keyTableAuthenticated(true);
        if (!rawAnchor.getAaguid().isPresent() && statementAaguid != null) {
          b.aaguid(statementAaguid);
        }
        verifiedAnchors.add(b.build());
      }
    }

    return new MtcJsonTrustSource(verifiedAnchors);
  }

  /**
   * Parses a standalone {@link MtcTrustAnchor} JSON object (e.g. an enterprise vendor key
   * manifest).
   */
  public static MtcJsonTrustSource fromTrustAnchorJson(@NonNull String json) throws IOException {
    ObjectMapper mapper = JacksonCodecs.json();
    MtcTrustAnchor anchor = mapper.readValue(json, MtcTrustAnchor.class);
    return new MtcJsonTrustSource(Collections.singletonList(anchor));
  }

  @Override
  public Optional<MtcTrustAnchor> findMtcTrustAnchor(
      ByteArray caId, Optional<ByteArray> aaguid) {
    List<MtcTrustAnchor> candidates = anchorsByCaId.get(caId);
    if (candidates == null || candidates.isEmpty()) {
      return Optional.empty();
    }
    for (MtcTrustAnchor candidate : candidates) {
      if (!candidate.getAaguid().isPresent()
          || !aaguid.isPresent()
          || candidate.getAaguid().get().equals(aaguid.get())) {
        return Optional.of(candidate);
      }
    }
    return Optional.empty();
  }
}
