package com.yubico.webauthn

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.TestAuthenticator.AttestationMaker
import com.yubico.webauthn.attestation.mtc.CompositeMtcTrustSource
import com.yubico.webauthn.attestation.mtc.FidoMtcLogEntry
import com.yubico.webauthn.attestation.mtc.MerkleInclusion
import com.yubico.webauthn.attestation.mtc.MtcAttestationInfo
import com.yubico.webauthn.attestation.mtc.MtcBatchKeyEntry
import com.yubico.webauthn.attestation.mtc.MtcCheckpoint
import com.yubico.webauthn.attestation.mtc.MtcJsonTrustSource
import com.yubico.webauthn.attestation.mtc.MtcProof
import com.yubico.webauthn.attestation.mtc.MtcSubtree
import com.yubico.webauthn.attestation.mtc.MtcTrustAnchor
import com.yubico.webauthn.attestation.mtc.MtcTrustSource
import com.yubico.webauthn.data.AttestationConveyancePreference
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.RegistrationExtensionInputs
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.exception.RegistrationFailedException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.runner.RunWith
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.Collections
import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.util.Failure
import scala.util.Success
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class MtcAttestationSpec extends AnyFunSpec with Matchers {

  if (Security.getProvider("BC") == null) {
    Security.addProvider(new BouncyCastleProvider())
  }

  private val jsonFactory = JsonNodeFactory.instance

  // Golden vectors from Fidont OpenSK MTC Enterprise & Batch Attestation
  private val FidontAaguid = ByteArray.fromHex("deadbeef000000000000deadbeef0000")
  private val BatchCaId = ByteArray.fromBase64Url("g5k_AQE")
  private val EnterpriseCaId = ByteArray.fromBase64Url("g5k_AQI")
  private val LogNumber = 7
  private val LeafIndex = 0L
  private val MtcSerial = 1970324836974592L // (7L << 48) | 0L
  private val NotBefore = 1792281600L // 2026-10-18T00:00:00Z
  private val NotAfter = 2107641600L // 2036-10-15T00:00:00Z
  private val ValidInstant = Instant.ofEpochSecond(1792700000L) // 2026-10-22T20:13:20Z
  private val ValidClock = Clock.fixed(ValidInstant, ZoneOffset.UTC)
  private val DeviceSerial = "123456"

  private val EnterpriseCosePublicKey = ByteArray.fromBase64Url(
    "owEHAzgvIFkFINzYZIhJKP3OLxMPdmyU1f8bD5Drf3ZdXIGb0RnVNic4T947v8FBsceKALZ5WDYhaztebO08ntMVXBH7V2OlNMWbzXfzuy8poYZuqgZUV9EwJJIg4T2t0cAW3gXScvC2UaJn1In32wPSGh12nTDpu3lT3U7yN47XUTbUdqrA0hc33M3rZq-aDbacOj_X1m7mGcvdp_u6slrrCAby9gKz1sLFOmF2EHFpfbtPkwT8jTNkvxW8puQdoWPYpUkNkVV5RRkNpN9Q75whss4x8i0HXVuddJXj_B-ByKQ742kQCWVz2uNeNhIzpeV7vNXcRfhbHLnRt_9vMPRyZqfr44JsgQNZppT9mAnhG4lgl2QgoLfA29N8O55172LPdanlMggbqreSaL3nnUoqjNMmkOe09XnFRhKi-O7UncLNFNDPwsRvXLlKwEZLfAyZVkCWilMTbDO1cKrrw8DMFAJhoMQde2ujjOLNTmC9NfChq7mLC0bBqSYfiOztlunetIGyB3RBEHV_07ePlzC205eKzb5TS8UkI7x3ZqyT1QA5X7eOduRg6dailUj2qfZBHvTaKKcULJgsk8CjPAzBk3_k2C4mOIWg8rAfd62JPHdJoTazQc88N13ySdsYNRt5IFryu4NWLE8l85X4VfGf-qkeo44tDJF1dGrU7cJhIrd_-Ur_np2fdzDnHcMyNrI-gZOCofNR5zqZdhe7qcrOQmFhkPaj9A_spZmFst0yzeC3zW9H97sS8SrBBTLNDWKUMXgjcBBpiTes3Y5slsbGWag24jSNKH_vSBvPp6Ot-rbaJV5hPLNZWOwkuDXKejtHzx9HNksaGbK7e1Zl-Ig2iGvajAbHOQQSUfAcMNV360xbtIy-Bn6DG4x3xYdeWsurk1FbSuvz4vFdc8jT3EPIODx7bpKdl9ZTdzXGocuPwx5SR9YxpBcNzhvQUnSL0-2Xs9Mt0P50hmkhioNp2KyRYgjNl4KBzws3ezXWwN-96TVv4j4brhKsefh-p5-YrPGI2MtCE0a8VNIqvIBHXeo5Uho2XAuUjDQ1kp8801SmmNmLEXTYCLlKkAw5vVQN7ZS-9mIU_0TawtiWrDk3A6ENFJ9WT3xNNjjhZs_JClJ_rq3VH3hLq2K2R9Uc9zFL9hX-eYmzJFNIX7KCvxWRanF0-lSy9fY_kYJa95PlbYEuvWt1ILBvu9Q4DEU-6yKAac8hHhdI0AgBfsqMWb3RYVtFrGKrqsH-TB7D2MEwULE0U1M7ehp6T3DUAOrsW5oV4sLqDPiyc40IlxYJtQiFoX2BVc_WOM3Basi3pHO5JG9ITD7b1QXZ8KD0hVDf_71AVU_2PPE7vNeN-667SSMCcNusLsnHNWrMOdj6AF0m1q_WRDYHZUlRUqnWhU8mXarGi2GuaCtZspQ7bS1FXtzxtV5F7i-dpFaJX0_DNEfPU9cBu5vwnQAuIyoeXRULe9NswbGA8Ow8PJHjU7DvMhIooKzBnCpSnfVuMRWv3UwlqYNG7Jaw10sYyEwqfAYOaaXjmrh7sL0E_TRoHVQmKkBICHqY_-dc-ViQyuwiyiNsDq2-ovnm_5fQwxX-m81i4GIBhjsTp_12ZVhVyrusmtVmHhLVNDvFYXPuxZbg4jCH3qzFAzEEmRu2h-5rwV4SXuTA6p3m0xt_ydnjsZ-28VKbQ96iuMwMgE_ZcL49zDVA9EjEbtwYrMjlU7dD2dQfH7TwO55jao5FLOyCfzyN0yTvipUrnCUOQFI6rwI"
  )
  private val ExpectedPubKeyHash = ByteArray.fromHex(
    "441ffb4758c7bb9eb3761be451e86239c6168c7593db71efca18102e73036ba6"
  )
  private val ExpectedLeafHash = ByteArray.fromHex(
    "73f62de9b3d74baa6e4d3a7bc0c02c344daabd6018bea7cb3c0075ae99519064"
  )
  private val ExpectedEnterpriseRootHash = ByteArray.fromBase64Url(
    "Jm8we_dJthE0X0JSq1xc_joQUs9WS-SQzBPpmkXJqHs"
  )
  private val ExpectedSubtreeCheckpoint = ByteArray.fromHex(
    "4649444f2d4d54432d535542545245452d434845434b504f494e542d56310000000583993f01020007000000000000000000000008266f307bf749b611345f4252ab5c5cfe3a1052cf564be490cc13e99a45c9a87b"
  )
  private val EnterpriseMtcProofBytes = ByteArray.fromBase64Url(
    "AAYxMjM0NTYAAAAAAAAAAAAAAAgAYAUR4uZ_FvWJr-TpcN46QNILQkiBjidf95-ZDnQ5uF9YmNjWkLSHrQBumpwQ2cUggDNBfF0Obf8_cAudHH8CJFgoFWvyGhl30KALcM5zQ4qsHpjuQ3uWfc0keVaY4Tl24AAAAA"
  )
  private val EnterpriseSubtreeSignature = ByteArray.fromBase64Url(
    "AAAAAAAAAAUAAAAELMNoZ1bGFoM6hHMn0KsFZGK8S0z2BkLvwlrRAPJXuxovPiJ3SS7j_ilpiRNEsR6NGAnxTtSj0VaZ-hubB2I9J1mSJvKbK_Zm6K_6pjrCZnSxHkKg1VMd4645jPz563SdCArBP-fZIzDDKrwDRIRu93wa9ZmVlYbFVjW-Uqcm4rujvFWzaRuVNa0de4XIzvNhYk6eGfQLiCpIYXzQQE2B7jL0KOGIyIjwufP_psjNEaqTNLy5XuFawQBlT6uQORWYGE3otnHTmtH8p26_qN4PEoIUbz6kcWPxVPfFq-mI5rHacl8fGkDB4Xfk1ZYcQU88IKXVPDY_56Bsd6RPZ_g8N_E9bVGk7LBjWzgPSfBlwfugoHBymGv0-mOqihIGPUv0uNeHi6MXqvdY47f95wkOs8nZQbXSl5cT4CtGwSvvsOetNBwDzxFoHGcan5ovwMZS6VOj00eQLgcpvRnd-nhDlUV74Dti7tmrza2-YGKbYpRAuPW3tXjETUfR3YvmOKcck9LnDzNE9y08lvfAkaaubFnvz2-ow_zEZtQ3VEUgeO7KpNG9Ddh4tAS2xMdMdEK7__OxF3RqAC9SyPuE7_Hr-5DCzYfU0Hw2gT-umdK6Pc4jqJFGNjq_lD6E0kav_lYxMpLbK1hikcwsHNJHkKfUykeExLyZb32TfMnKTnPO__hvVOIavLhuF5IvdTxeQRuufj2wzKDcV5-3Pj1QAmuszrP77Ei558NXDjJJET0SWqsyM9JmNt1ZZEq6CvtlJjpLvdUpcabn5G8uuW9nQZtissk6E0btD60qoX1T8Fh5aqMaiqZ-8pO_y0WI8NFIPRIHp2hjkI0sod9YSflLQMfl-dvyLJrGEi_O7Urky1kOe88itIlOkjjdupUadS1JVrq1NNArQPkyZ2UPN-1v9izZ-3jybwGDDIqc6SqyGACkCDmWao6d3fWyY81yOryYCYQDUJcRMJ9My01DuXo5Yv9ds0Ed2-ChZme2h6xYxWTKhw34H7I1t-U0wtIpwmxPTl7k6zGqMr1O2FpfsZvL_5JxK_wgkoXildj10Nf_fTEG67hFu6FqJUIx8zyStTIeaEq36e2PmQGEBYgwPkjUK3Vel2Nfo-3lB9kkyp6eAvjGh2jswYTaiYpmyBoa3zEdWp40ooBiuZlbbJH7RRnVp9tvYJEG2RfzgplnE3Dc-qq7FPq2E_vOwz0Dhj1NsOmQvowEY8JFok-cat2R-y18OpqoUxGMdYopPYbJONZ6JDBcw2TI_azOR6LSeMoXc_J7fpU16YSY6WmXZs0XVt-BHhh1JpNhfqWXA-qR4niqzu6HhmJeqVwEtTtJofWxcYPDaZfSPo9DVaqEp1CRGU4uuJLbfc8FiCS81r1kOV38upVrfP1CdIOcysMnYSgbdiPTonhMRZ3f1AAhQU1jQpMRIsipM_57x0wuO5VWabqBvlf1tCfnl9ZJhoSkH7VAA17NbfcRDKmL5ks4hpaqyqxL1Ki9QwAAAAV1aXMVf2sCGPrv1QT2AXe_qFt77_VC6Pa1WZS7ib2nax6EtvltrCN0HKZjG1SYOhshh8RLMef-fF8ufSllDE9dHag9WnLcG9ByFMJiTqbdYbKxPFw9PEM-kjd3kmhmbVL71nCcl-ahUmc7gI_7JIp1gw0RHw8tI8pX2ltQwCExCN2DNQQCRmwVR70lLfPukCkF7ltxoe_O8nBBJtoKHPJ2"
  )
  private val LmsIntermediateCert0DerB64 =
    "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"

  private val FidontEnterprisePrivateKeyPkcs8B64 =
    "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"

  private lazy val fidontEnterprisePrivateKey: PrivateKey = {
    val der = Base64.getDecoder.decode(FidontEnterprisePrivateKeyPkcs8B64)
    KeyFactory.getInstance("ML-DSA-44", "BC").generatePrivate(new PKCS8EncodedKeySpec(der))
  }

  private def signMlDsa44(privateKey: PrivateKey, data: ByteArray): ByteArray = {
    val sig = Signature.getInstance("ML-DSA-44", "BC")
    sig.initSign(privateKey)
    sig.update(data.getBytes)
    new ByteArray(sig.sign())
  }

  private def buildSingleLeafMtcProof(deviceSerial: Option[String] = None): ByteArray = {
    val extBytes = deviceSerial.map(_.getBytes(StandardCharsets.UTF_8)).getOrElse(Array.emptyByteArray)
    // TLS MTCProof: uint16 ext_len || ext || uint48 start(0) || uint48 end(1) || uint16 proof_len(0) || uint24 sig_len(0)
    val buf = ByteBuffer.allocate(2 + extBytes.length + 6 + 6 + 2 + 3)
    buf.putShort((extBytes.length & 0xffff).toShort)
    buf.put(extBytes)
    buf.put(new Array[Byte](6)) // start = 0
    buf.put(Array[Byte](0, 0, 0, 0, 0, 1)) // end = 1
    buf.putShort(0.toShort) // proof_len = 0
    buf.put(Array[Byte](0, 0, 0)) // sig_len = 0
    new ByteArray(buf.array())
  }

  private def makeMtcAttestationMaker(
      formatName: String = "mtc",
      alg: COSEAlgorithmIdentifier,
      signFn: ByteArray => ByteArray,
      caId: ByteArray,
      serial: Long,
      notBeforeOpt: Option[Long] = Some(NotBefore),
      notAfterOpt: Option[Long] = Some(NotAfter),
      fwVersionOpt: Option[Long] = None,
      mtcProofOpt: Option[ByteArray] = None,
      inlinePubKeyOpt: Option[ByteArray] = None,
  ): AttestationMaker = new AttestationMaker {
    override val format: String = formatName
    override def makeAttestationStatement(
        authDataBytes: ByteArray,
        clientDataJson: ByteArray,
    ): ObjectNode = {
      val signedData = authDataBytes.concat(Crypto.sha256(clientDataJson))
      val sig = signFn(signedData)

      val mtcCert = jsonFactory.objectNode()
      mtcCert.set("caId", jsonFactory.binaryNode(caId.getBytes))
      mtcCert.set("serial", jsonFactory.numberNode(serial))
      if (notBeforeOpt.isDefined) {
        mtcCert.set("notBefore", jsonFactory.numberNode(notBeforeOpt.get))
      }
      if (notAfterOpt.isDefined) {
        mtcCert.set("notAfter", jsonFactory.numberNode(notAfterOpt.get))
      }
      if (fwVersionOpt.isDefined) {
        mtcCert.set("fwVersion", jsonFactory.numberNode(fwVersionOpt.get))
      }
      if (mtcProofOpt.isDefined) {
        mtcCert.set("mtcProof", jsonFactory.binaryNode(mtcProofOpt.get.getBytes))
      }

      val attStmt = jsonFactory.objectNode()
      attStmt.set("alg", jsonFactory.numberNode(alg.getId))
      attStmt.set("sig", jsonFactory.binaryNode(sig.getBytes))
      attStmt.set("mtcCert", mtcCert)
      if (inlinePubKeyOpt.isDefined) {
        attStmt.set("pubKey", jsonFactory.binaryNode(inlinePubKeyOpt.get.getBytes))
      }
      attStmt
    }
  }

  private def createDummyRepo(): CredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String) = Collections.emptySet()
    override def getUserHandleForUsername(username: String) = Optional.empty()
    override def getUsernameForUserHandle(userHandle: ByteArray) = Optional.empty()
    override def lookup(credentialId: ByteArray, userHandle: ByteArray) = Optional.empty()
    override def lookupAll(credentialId: ByteArray) = Collections.emptySet()
  }

  describe("MTC Cryptographic Primitives & Golden Vectors") {

    it("computes the exact canonical COSE_Key SHA-256 hash for Fidont ML-DSA-44 key") {
      val pubKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(EnterpriseCosePublicKey)
      pubKeyHash should equal(ExpectedPubKeyHash)
    }

    it("serializes FidoMtcLogEntry and computes the exact RFC 9162 leaf hash") {
      val extBytes = new ByteArray(DeviceSerial.getBytes(StandardCharsets.UTF_8))
      extBytes.getHex should equal("313233343536")

      val entry = FidoMtcLogEntry
        .builder()
        .caId(EnterpriseCaId)
        .notBefore(NotBefore)
        .notAfter(NotAfter)
        .aaguid(FidontAaguid)
        .fwVersion(Optional.empty())
        .pubKeyHash(ExpectedPubKeyHash)
        .serial(MtcSerial)
        .extensions(extBytes)
        .build()

      entry.toBytes.size() should equal(88)
      entry.computeLeafHash() should equal(ExpectedLeafHash)
    }

    it("parses the 121-byte TLS MTCProof and evaluates the RFC 9162 inclusion proof to the MDS subtree rootHash") {
      val parsed = MtcProof.parse(EnterpriseMtcProofBytes)
      parsed.getStart should equal(0L)
      parsed.getEnd should equal(8L)
      new String(parsed.getExtensions.getBytes, StandardCharsets.UTF_8) should equal(DeviceSerial)
      parsed.getInclusionProof.size() should equal(3)

      val computedRoot = MerkleInclusion.evaluateInclusionProof(
        LeafIndex,
        parsed.getStart,
        parsed.getEnd,
        ExpectedLeafHash,
        parsed.getInclusionProof,
      )
      computedRoot should equal(Optional.of(ExpectedEnterpriseRootHash))
    }

    it("builds the exact 85-byte FidoMtcSubtreeCheckpoint and verifies the RFC 8554 HSS-LMS signature") {
      val checkpoint = MtcCheckpoint.buildCheckpointBytes(
        EnterpriseCaId,
        LogNumber,
        0L,
        8L,
        ExpectedEnterpriseRootHash,
      )
      checkpoint should equal(ExpectedSubtreeCheckpoint)
      checkpoint.size() should equal(85)

      val lmsCert = CertificateParser.parseDer(Base64.getDecoder.decode(LmsIntermediateCert0DerB64))
      MtcCheckpoint.verifyWithCertificate(
        lmsCert,
        checkpoint,
        EnterpriseSubtreeSignature,
        -46L,
      ) should be(true)
    }

    it("parses a standalone MDS3 MetadataStatement JSON and authenticates HSS-LMS subtree checkpoints") {
      val mdsJson =
        s"""{
           |  "aaguid": "deadbeef-0000-0000-0000-deadbeef0000",
           |  "description": "Fidont Post-Quantum Authenticator",
           |  "attestationRootCertificates": ["$LmsIntermediateCert0DerB64"],
           |  "mtcTrustAnchors": [
           |    {
           |      "caId": "g5k_AQI",
           |      "hashAlg": "sha-256",
           |      "maxBatchWindow": 315360000,
           |      "subtrees": [
           |        {
           |          "logNumber": 7,
           |          "start": 0,
           |          "end": 8,
           |          "rootHash": "Jm8we_dJthE0X0JSq1xc_joQUs9WS-SQzBPpmkXJqHs",
           |          "alg": -46,
           |          "signature": "${EnterpriseSubtreeSignature.getBase64Url}"
           |        }
           |      ],
           |      "revokedSerials": [],
           |      "batchKeys": []
           |    }
           |  ]
           |}""".stripMargin

      val source = MtcJsonTrustSource.fromMetadataStatementJson(mdsJson)
      val anchorOpt = source.findMtcTrustAnchor(EnterpriseCaId, Optional.of(FidontAaguid))
      anchorOpt.isPresent should be(true)
      anchorOpt.get().getSubtrees.size() should equal(1)
      anchorOpt.get().getSubtrees.get(0).getSigningCert.isPresent should be(true)
    }
  }

  describe("RelyingParty.startRegistration MTC Request Options") {

    it("includes attestationFormats and mtcDebug extension when configured") {
      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
        .attestationFormats("mtc", "packed")
        .build()

      val options = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("alice")
              .displayName("Alice")
              .id(new ByteArray(Array[Byte](1, 2, 3, 4)))
              .build()
          )
          .extensions(RegistrationExtensionInputs.builder().mtcDebug(true).build())
          .build()
      )

      options.getAttestation should equal(AttestationConveyancePreference.DIRECT)
      options.getAttestationFormats.isPresent should be(true)
      options.getAttestationFormats.get().asScala should equal(List("mtc", "packed"))
      options.getExtensions.getMtcDebug should equal(Optional.of(java.lang.Boolean.TRUE))

      val json = JacksonCodecs.json().readTree(options.toCredentialsCreateJson)
      val pkNode = json.get("publicKey")
      pkNode.get("attestation").asText() should equal("direct")
      pkNode.get("attestationFormats").get(0).asText() should equal("mtc")
      pkNode.get("attestationFormats").get(1).asText() should equal("packed")
      pkNode.get("extensions").get("mtcDebug").asBoolean() should be(true)
    }

    it("omits attestationFormats when attestation conveyance preference is NONE") {
      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .attestationConveyancePreference(AttestationConveyancePreference.NONE)
        .attestationFormats("mtc", "packed")
        .build()

      val options = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("alice")
              .displayName("Alice")
              .id(new ByteArray(Array[Byte](1, 2, 3, 4)))
              .build()
          )
          .build()
      )

      options.getAttestation should equal(AttestationConveyancePreference.NONE)
      options.getAttestationFormats.isPresent should be(false)
    }
  }

  describe("RelyingParty.finishRegistration End-to-End MTC Ceremonies") {

    it("verifies Batch fmt='mtc' where the public key is omitted from attStmt and resolved from MDS batchKeys") {
      val batchKeypair = TestAuthenticator.generateEcKeypair()
      val batchCoseKey = WebAuthnTestCodecs.ecPublicKeyToCose(
        batchKeypair.getPublic.asInstanceOf[java.security.interfaces.ECPublicKey]
      )
      val batchPubKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(batchCoseKey)
      val batchLeaf = FidoMtcLogEntry
        .builder()
        .caId(BatchCaId)
        .notBefore(NotBefore)
        .notAfter(NotAfter)
        .aaguid(FidontAaguid)
        .fwVersion(Optional.empty())
        .pubKeyHash(batchPubKeyHash)
        .serial(MtcSerial)
        .extensions(new ByteArray(Array.emptyByteArray))
        .build()
      val batchRootHash = batchLeaf.computeLeafHash() // single-leaf subtree (start=0, end=1)

      val mdsAnchor = MtcTrustAnchor
        .builder()
        .caId(BatchCaId)
        .logNumber(LogNumber)
        .hashAlg("sha-256")
        .maxBatchWindow(315360000L)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(1L)
              .rootHash(batchRootHash)
              .alg(-46)
              .signature(new ByteArray(new Array[Byte](32)))
              .build()
          ).asJava
        )
        .batchKeys(
          List(
            MtcBatchKeyEntry
              .builder()
              .serial(MtcSerial)
              .alg(-7)
              .coseKey(batchCoseKey)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .keyTableAuthenticated(true)
        .build()

      val trustSource: MtcTrustSource = (caId, _) =>
        if (caId == BatchCaId) Optional.of(mdsAnchor) else Optional.empty()

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
        .attestationFormats("mtc", "packed")
        .mtcTrustSource(trustSource)
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("alice")
              .displayName("Alice")
              .id(new ByteArray(Array[Byte](1, 2, 3, 4)))
              .build()
          )
          .build()
      )

      val maker = makeMtcAttestationMaker(
        alg = COSEAlgorithmIdentifier.ES256,
        signFn = data =>
          TestAuthenticator.sign(data, batchKeypair.getPrivate, COSEAlgorithmIdentifier.ES256),
        caId = BatchCaId,
        serial = MtcSerial,
        mtcProofOpt = Some(buildSingleLeafMtcProof()),
      )

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(aaguid = FidontAaguid)
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      // Verify attStmt on the wire does NOT contain pubKey
      credential.getResponse.getAttestation.getAttestationStatement.has("pubKey") should be(false)

      val result = rp.finishRegistration(
        FinishRegistrationOptions.builder().request(request).response(credential).build()
      )

      result.isAttestationTrusted should be(true)
      result.getAttestationType should equal(AttestationType.BASIC)
      result.getMtcAttestation.isPresent should be(true)
      val mtcInfo = result.getMtcAttestation.get()
      mtcInfo.getKeySource should equal(MtcAttestationInfo.KeySource.MDS_BATCH_KEY_TABLE)
      mtcInfo.isEnterprise should be(false)
      mtcInfo.isProofVerified should be(true)
      mtcInfo.getCaId should equal(BatchCaId)
      mtcInfo.getSerial should equal(MtcSerial)
      mtcInfo.getSubtreeRootHash should equal(Optional.of(batchRootHash))
    }

    it("verifies Enterprise fmt='mtc' where the key and deviceSerial come from a vendor manifest") {
      val mdsSubtreeAnchor = MtcTrustAnchor
        .builder()
        .caId(EnterpriseCaId)
        .logNumber(LogNumber)
        .hashAlg("sha-256")
        .maxBatchWindow(315360000L)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(8L)
              .rootHash(ExpectedEnterpriseRootHash)
              .alg(-46)
              .signature(EnterpriseSubtreeSignature)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .keyTableAuthenticated(false)
        .build()

      val enterpriseManifestAnchor = MtcTrustAnchor
        .builder()
        .caId(EnterpriseCaId)
        .logNumber(LogNumber)
        .hashAlg("sha-256")
        .maxBatchWindow(315360000L)
        .batchKeys(
          List(
            MtcBatchKeyEntry
              .builder()
              .serial(MtcSerial)
              .alg(-48)
              .coseKey(EnterpriseCosePublicKey)
              .deviceSerial(DeviceSerial)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .keyTableAuthenticated(true)
        .build()

      val compositeTrustSource = new CompositeMtcTrustSource(
        List[MtcTrustSource](
          (caId, _) => if (caId == EnterpriseCaId) Optional.of(mdsSubtreeAnchor) else Optional.empty(),
          (caId, _) =>
            if (caId == EnterpriseCaId) Optional.of(enterpriseManifestAnchor) else Optional.empty(),
        ).asJava
      )

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.ENTERPRISE)
        .attestationFormats("mtc", "packed")
        .mtcTrustSource(compositeTrustSource)
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("enterprise-user")
              .displayName("Enterprise User")
              .id(new ByteArray(Array[Byte](9, 9, 9, 9)))
              .build()
          )
          .build()
      )

      val maker = makeMtcAttestationMaker(
        alg = COSEAlgorithmIdentifier.ML_DSA_44,
        signFn = data => signMlDsa44(fidontEnterprisePrivateKey, data),
        caId = EnterpriseCaId,
        serial = MtcSerial,
        mtcProofOpt = Some(EnterpriseMtcProofBytes),
      )

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(aaguid = FidontAaguid)
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      credential.getResponse.getAttestation.getAttestationStatement.has("pubKey") should be(false)

      val result = rp.finishRegistration(
        FinishRegistrationOptions.builder().request(request).response(credential).build()
      )

      result.isAttestationTrusted should be(true)
      result.getAttestationType should equal(AttestationType.ATTESTATION_CA)
      result.getMtcAttestation.isPresent should be(true)
      val mtcInfo = result.getMtcAttestation.get()
      mtcInfo.getKeySource should equal(MtcAttestationInfo.KeySource.ENTERPRISE_MANIFEST)
      mtcInfo.isEnterprise should be(true)
      mtcInfo.isProofVerified should be(true)
      mtcInfo.getDeviceSerial should equal(Optional.of(DeviceSerial))
      mtcInfo.getLeafHash should equal(Optional.of(ExpectedLeafHash))
      mtcInfo.getSubtreeRootHash should equal(Optional.of(ExpectedEnterpriseRootHash))
    }

    it("verifies Enterprise fmt='mtc' via the mtc-debug extension without any vendor manifest") {
      // RP ONLY has the public MDS subtree rootHash (batchKeys is empty)
      val mdsOnlyAnchor = MtcTrustAnchor
        .builder()
        .caId(EnterpriseCaId)
        .logNumber(LogNumber)
        .hashAlg("sha-256")
        .maxBatchWindow(315360000L)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(8L)
              .rootHash(ExpectedEnterpriseRootHash)
              .alg(-46)
              .signature(EnterpriseSubtreeSignature)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .keyTableAuthenticated(false)
        .build()

      val mdsOnlyTrustSource: MtcTrustSource = (caId, _) =>
        if (caId == EnterpriseCaId) Optional.of(mdsOnlyAnchor) else Optional.empty()

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.ENTERPRISE)
        .attestationFormats("mtc", "packed")
        .mtcTrustSource(mdsOnlyTrustSource)
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("debug-enterprise-user")
              .displayName("Debug Enterprise User")
              .id(new ByteArray(Array[Byte](7, 7, 7, 7)))
              .build()
          )
          .extensions(RegistrationExtensionInputs.builder().mtcDebug(true).build())
          .build()
      )

      // Authenticator populates authenticatorData.extensions["mtc-debug"] = { pubKey, deviceSerial }
      val mtcDebugNode = jsonFactory.objectNode()
      mtcDebugNode.set("pubKey", jsonFactory.binaryNode(EnterpriseCosePublicKey.getBytes))
      mtcDebugNode.set("deviceSerial", jsonFactory.textNode(DeviceSerial))
      val authExtsNode = jsonFactory.objectNode()
      authExtsNode.set("mtc-debug", mtcDebugNode)

      val maker = makeMtcAttestationMaker(
        alg = COSEAlgorithmIdentifier.ML_DSA_44,
        signFn = data => signMlDsa44(fidontEnterprisePrivateKey, data),
        caId = EnterpriseCaId,
        serial = MtcSerial,
        mtcProofOpt = Some(EnterpriseMtcProofBytes),
      )

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(
        aaguid = FidontAaguid,
        authenticatorExtensions = Some(authExtsNode),
      )
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      val result = rp.finishRegistration(
        FinishRegistrationOptions.builder().request(request).response(credential).build()
      )

      result.isAttestationTrusted should be(true)
      result.getAttestationType should equal(AttestationType.ATTESTATION_CA)
      result.getMtcAttestation.isPresent should be(true)
      val mtcInfo = result.getMtcAttestation.get()
      mtcInfo.getKeySource should equal(MtcAttestationInfo.KeySource.MTC_DEBUG_EXTENSION)
      mtcInfo.isEnterprise should be(true)
      mtcInfo.isProofVerified should be(true)
      mtcInfo.getDeviceSerial should equal(Optional.of(DeviceSerial))
      mtcInfo.getLeafHash should equal(Optional.of(ExpectedLeafHash))
      mtcInfo.getSubtreeRootHash should equal(Optional.of(ExpectedEnterpriseRootHash))
    }

    it("rejects attStmt that contains an inline pubKey") {
      val mdsOnlyAnchor = MtcTrustAnchor
        .builder()
        .caId(EnterpriseCaId)
        .logNumber(LogNumber)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(8L)
              .rootHash(ExpectedEnterpriseRootHash)
              .alg(-46)
              .signature(EnterpriseSubtreeSignature)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .build()

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.ENTERPRISE)
        .mtcTrustSource((caId, _) =>
          if (caId == EnterpriseCaId) Optional.of(mdsOnlyAnchor) else Optional.empty()
        )
        .allowUntrustedAttestation(false)
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("inline-pubkey-user")
              .displayName("Inline PubKey User")
              .id(new ByteArray(Array[Byte](5, 5, 5, 5)))
              .build()
          )
          .build()
      )

      val maker = makeMtcAttestationMaker(
        alg = COSEAlgorithmIdentifier.ML_DSA_44,
        signFn = data => signMlDsa44(fidontEnterprisePrivateKey, data),
        caId = EnterpriseCaId,
        serial = MtcSerial,
        mtcProofOpt = Some(EnterpriseMtcProofBytes),
        inlinePubKeyOpt = Some(EnterpriseCosePublicKey),
      )

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(aaguid = FidontAaguid)
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      val attempt = Try(
        rp.finishRegistration(
          FinishRegistrationOptions.builder().request(request).response(credential).build()
        )
      )
      attempt shouldBe a[Failure[_]]
      attempt.failed.get shouldBe a[RegistrationFailedException]
    }

    it("rejects mtc-debug containing deviceSerial when RP did not request ENTERPRISE attestation") {
      val mdsOnlyAnchor = MtcTrustAnchor
        .builder()
        .caId(EnterpriseCaId)
        .logNumber(LogNumber)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(8L)
              .rootHash(ExpectedEnterpriseRootHash)
              .alg(-46)
              .signature(EnterpriseSubtreeSignature)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .build()

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
        .mtcTrustSource((caId, _) =>
          if (caId == EnterpriseCaId) Optional.of(mdsOnlyAnchor) else Optional.empty()
        )
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("privacy-leak-user")
              .displayName("Privacy Leak User")
              .id(new ByteArray(Array[Byte](6, 6, 6, 6)))
              .build()
          )
          .extensions(RegistrationExtensionInputs.builder().mtcDebug(true).build())
          .build()
      )

      val mtcDebugNode = jsonFactory.objectNode()
      mtcDebugNode.set("pubKey", jsonFactory.binaryNode(EnterpriseCosePublicKey.getBytes))
      mtcDebugNode.set("deviceSerial", jsonFactory.textNode(DeviceSerial))
      val authExtsNode = jsonFactory.objectNode()
      authExtsNode.set("mtc-debug", mtcDebugNode)

      val maker = makeMtcAttestationMaker(
        alg = COSEAlgorithmIdentifier.ML_DSA_44,
        signFn = data => signMlDsa44(fidontEnterprisePrivateKey, data),
        caId = EnterpriseCaId,
        serial = MtcSerial,
        mtcProofOpt = Some(EnterpriseMtcProofBytes),
      )

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(
        aaguid = FidontAaguid,
        authenticatorExtensions = Some(authExtsNode),
      )
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      val attempt = Try(
        rp.finishRegistration(
          FinishRegistrationOptions.builder().request(request).response(credential).build()
        )
      )
      attempt shouldBe a[Failure[_]]
      attempt.failed.get.getMessage should include("deviceSerial")
    }

    it("verifies proof-less mtcKeyRef ({ caId, serial }) using the 7-field WebAuthn L4 mtc-debug extension") {
      val mdsOnlyAnchor = MtcTrustAnchor
        .builder()
        .caId(EnterpriseCaId)
        .logNumber(LogNumber)
        .hashAlg("sha-256")
        .maxBatchWindow(315360000L)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(8L)
              .rootHash(ExpectedEnterpriseRootHash)
              .alg(-46)
              .signature(EnterpriseSubtreeSignature)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .keyTableAuthenticated(false)
        .build()

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.ENTERPRISE)
        .attestationFormats("mtc", "packed")
        .mtcTrustSource((caId, _) =>
          if (caId == EnterpriseCaId) Optional.of(mdsOnlyAnchor) else Optional.empty()
        )
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("keyref-debug-user")
              .displayName("KeyRef Debug User")
              .id(new ByteArray(Array[Byte](8, 8, 8, 8)))
              .build()
          )
          .extensions(RegistrationExtensionInputs.builder().mtcDebug(true).build())
          .build()
      )

      // 7-field mtc-debug output carrying notBefore, notAfter, mtcProof, rootHash
      val mtcDebugNode = jsonFactory.objectNode()
      mtcDebugNode.set("pubKey", jsonFactory.binaryNode(EnterpriseCosePublicKey.getBytes))
      mtcDebugNode.set("deviceSerial", jsonFactory.textNode(DeviceSerial))
      mtcDebugNode.set("notBefore", jsonFactory.numberNode(NotBefore))
      mtcDebugNode.set("notAfter", jsonFactory.numberNode(NotAfter))
      mtcDebugNode.set("mtcProof", jsonFactory.binaryNode(EnterpriseMtcProofBytes.getBytes))
      mtcDebugNode.set("rootHash", jsonFactory.binaryNode(ExpectedEnterpriseRootHash.getBytes))
      val authExtsNode = jsonFactory.objectNode()
      authExtsNode.set("mtc-debug", mtcDebugNode)

      // Proof-less mtcKeyRef: only { caId, serial } in attStmt.mtcCert
      val maker = makeMtcAttestationMaker(
        alg = COSEAlgorithmIdentifier.ML_DSA_44,
        signFn = data => signMlDsa44(fidontEnterprisePrivateKey, data),
        caId = EnterpriseCaId,
        serial = MtcSerial,
        notBeforeOpt = None,
        notAfterOpt = None,
        mtcProofOpt = None,
      )

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(
        aaguid = FidontAaguid,
        authenticatorExtensions = Some(authExtsNode),
      )
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      // Verify mtcCert on wire only has caId and serial (mtcKeyRef)
      val mtcCertOnWire = credential.getResponse.getAttestation.getAttestationStatement.get("mtcCert")
      mtcCertOnWire.has("mtcProof") should be(false)
      mtcCertOnWire.has("notBefore") should be(false)

      val result = rp.finishRegistration(
        FinishRegistrationOptions.builder().request(request).response(credential).build()
      )

      result.isAttestationTrusted should be(true)
      result.getAttestationType should equal(AttestationType.ATTESTATION_CA)
      val mtcInfo = result.getMtcAttestation.get()
      mtcInfo.getKeySource should equal(MtcAttestationInfo.KeySource.MTC_DEBUG_EXTENSION)
      mtcInfo.isEnterprise should be(true)
      mtcInfo.isProofVerified should be(true)
      mtcInfo.getDeviceSerial should equal(Optional.of(DeviceSerial))
      mtcInfo.getNotBefore should equal(Optional.of(java.lang.Long.valueOf(NotBefore)))
      mtcInfo.getNotAfter should equal(Optional.of(java.lang.Long.valueOf(NotAfter)))
      mtcInfo.getSubtreeRootHash should equal(Optional.of(ExpectedEnterpriseRootHash))
    }

    it("commits firmwareVersion (CTAP 2.3 0x0E) in FidoMtcLogEntry and verifies via mtcEntryDesc") {
      val fwVersion = 0x00051405L // v5.20.5 (332805)
      val batchKeypair = TestAuthenticator.generateEcKeypair()
      val batchCoseKey = WebAuthnTestCodecs.ecPublicKeyToCose(
        batchKeypair.getPublic.asInstanceOf[java.security.interfaces.ECPublicKey]
      )
      val batchPubKeyHash = FidoMtcLogEntry.computeCanonicalCoseKeyHash(batchCoseKey)
      val batchLeaf = FidoMtcLogEntry
        .builder()
        .caId(BatchCaId)
        .notBefore(NotBefore)
        .notAfter(NotAfter)
        .aaguid(FidontAaguid)
        .fwVersion(Optional.of(java.lang.Long.valueOf(fwVersion)))
        .pubKeyHash(batchPubKeyHash)
        .serial(MtcSerial)
        .extensions(new ByteArray(Array.emptyByteArray))
        .build()
      val batchRootHash = batchLeaf.computeLeafHash()

      val mdsAnchor = MtcTrustAnchor
        .builder()
        .caId(BatchCaId)
        .logNumber(LogNumber)
        .hashAlg("sha-256")
        .maxBatchWindow(315360000L)
        .subtrees(
          List(
            MtcSubtree
              .builder()
              .logNumber(LogNumber)
              .start(0L)
              .end(1L)
              .rootHash(batchRootHash)
              .alg(-46)
              .signature(new ByteArray(new Array[Byte](32)))
              .build()
          ).asJava
        )
        .batchKeys(
          List(
            MtcBatchKeyEntry
              .builder()
              .serial(MtcSerial)
              .alg(-7)
              .coseKey(batchCoseKey)
              .build()
          ).asJava
        )
        .aaguid(FidontAaguid)
        .keyTableAuthenticated(true)
        .build()

      val rp = RelyingParty
        .builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test RP").build())
        .credentialRepository(createDummyRepo())
        .origins(Set("https://localhost").asJava)
        .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
        .mtcTrustSource((caId, _) =>
          if (caId == BatchCaId) Optional.of(mdsAnchor) else Optional.empty()
        )
        .clock(ValidClock)
        .build()

      val request = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("fw-user")
              .displayName("FW User")
              .id(new ByteArray(Array[Byte](3, 3, 3, 3)))
              .build()
          )
          .build()
      )

      val maker = new AttestationMaker {
        override val format: String = "mtc"
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: ByteArray,
        ): ObjectNode = {
          val signedData = authDataBytes.concat(Crypto.sha256(clientDataJson))
          val sig = TestAuthenticator.sign(
            signedData,
            batchKeypair.getPrivate,
            COSEAlgorithmIdentifier.ES256,
          )
          val mtcCert = jsonFactory.objectNode()
          mtcCert.set("caId", jsonFactory.binaryNode(BatchCaId.getBytes))
          mtcCert.set("serial", jsonFactory.numberNode(MtcSerial))
          mtcCert.set("notBefore", jsonFactory.numberNode(NotBefore))
          mtcCert.set("notAfter", jsonFactory.numberNode(NotAfter))
          mtcCert.set("firmwareVersion", jsonFactory.numberNode(fwVersion))
          mtcCert.set("mtcProof", jsonFactory.binaryNode(buildSingleLeafMtcProof().getBytes))

          val attStmt = jsonFactory.objectNode()
          attStmt.set("alg", jsonFactory.numberNode(-7))
          attStmt.set("sig", jsonFactory.binaryNode(sig.getBytes))
          attStmt.set("mtcCert", mtcCert)
          attStmt
        }
      }

      val (authData, credKeypair) = TestAuthenticator.createAuthenticatorData(aaguid = FidontAaguid)
      val clientData = TestAuthenticator.createClientData(challenge = request.getChallenge)
      val (credential, _, _) = TestAuthenticator.createCredential(
        authDataBytes = authData,
        credentialKeypair = credKeypair,
        attestationMaker = maker,
        clientDataJson = Some(clientData),
      )

      val result = rp.finishRegistration(
        FinishRegistrationOptions.builder().request(request).response(credential).build()
      )

      result.isAttestationTrusted should be(true)
      result.getAttestationType should equal(AttestationType.BASIC)
      result.getMtcAttestation.get().getFirmwareVersion should equal(
        Optional.of(java.lang.Long.valueOf(fwVersion))
      )
    }
  }
}
