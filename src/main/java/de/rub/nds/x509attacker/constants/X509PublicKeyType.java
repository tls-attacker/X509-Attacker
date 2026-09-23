/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.protocol.constants.MlDsaParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.constants.SlhDsaParameters;
import java.util.HashMap;
import java.util.Map;

public enum X509PublicKeyType {
    RSA("RSA", "1.2.840.113549.1.1.1"), // RFC3279
    DSA("DSA", "1.2.840.10040.4.1"), // RFC3279
    DH("Diffie-Hellman", "1.2.840.113549.1.3.1"), // RFC3279
    KEA("Key Exchange Algorithm", "2.16.840.1.101.2.1.1.22"), // RFC3279
    ECDH_ECDSA("Elliptic Curve", "1.2.840.10045.2.1"), // RFC3279, used for ECDH and ECDSA
    RSASSA_PSS("RSA-PSS", "1.2.840.113549.1.1.10"), // RFC4055
    RSAES_OAEP("RSA-OAEP", "1.2.840.113549.1.1.7"), // RFC4055
    GOST_R3411_94("GOST_R3411_94", "1.2.643.2.2.20"), // RFC4491
    GOST_R3411_2001("GOST_R3411_2001", "1.2.643.2.2.19"), // RFC4491
    GOST_R3411_2012("GOST_R3411_2001", "1.2.643.2.2.19"), // RFC4491
    ECDH_ONLY("ECDH", "1.3.132.1.12"), // RFC5480
    ECMQV("ECMQV", "1.3.132.1.13"), // RFC5480
    X25519("X25519", "1.3.101.110"), // RFC8410
    X448("X448", "1.3.101.111"), // RFC8410
    ED25519("Ed25519", "1.3.101.112"), // RFC8410
    ED448("Ed448", "1.3.101.113"), // RFC8410
    ML_DSA_44("ML-DSA-44", "2.16.840.1.101.3.4.3.17"), // RFC9881
    ML_DSA_65("ML-DSA-65", "2.16.840.1.101.3.4.3.18"), // RFC9881
    ML_DSA_87("ML-DSA-87", "2.16.840.1.101.3.4.3.19"), // RFC9881
    SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20"), // RFC9909,
    SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21"), // RFC9909,
    SLH_DSA_SHA2_192S("SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22"), // RFC9909,
    SLH_DSA_SHA2_192F("SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23"), // RFC9909,
    SLH_DSA_SHA2_256S("SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24"), // RFC9909,
    SLH_DSA_SHA2_256F("SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25"), // RFC9909,
    SLH_DSA_SHAKE_128S("SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26"), // RFC9909,
    SLH_DSA_SHAKE_128F("SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27"), // RFC9909,
    SLH_DSA_SHAKE_192S("SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28"), // RFC9909,
    SLH_DSA_SHAKE_192F("SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29"), // RFC9909,
    SLH_DSA_SHAKE_256S("SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30"), // RFC9909,
    SLH_DSA_SHAKE_256F("SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31"), // RFC9909,
    HASH_SLH_DSA_SHA2_128S_WITH_SHA256(
            "HashSLH-DSA-SHA2-128s-with-SHA256", "2.16.840.1.101.3.4.3.35"), // RFC9909,
    HASH_SLH_DSA_SHA2_128F_WITH_SHA256(
            "HashSLH-DSA-SHA2-128f-with-SHA256", "2.16.840.1.101.3.4.3.36"), // RFC9909,
    HASH_SLH_DSA_SHA2_192S_WITH_SHA512(
            "HashSLH-DSA-SHA2-192s-with-SHA512", "2.16.840.1.101.3.4.3.37"), // RFC9909,
    HASH_SLH_DSA_SHA2_192F_WITH_SHA512(
            "HashSLH-DSA-SHA2-192f-with-SHA512", "2.16.840.1.101.3.4.3.38"), // RFC9909,
    HASH_SLH_DSA_SHA2_256S_WITH_SHA512(
            "HashSLH-DSA-SHA2-256s-with-SHA512", "2.16.840.1.101.3.4.3.39"), // RFC9909,
    HASH_SLH_DSA_SHA2_256F_WITH_SHA512(
            "HashSLH-DSA-SHA2-256f-with-SHA512", "2.16.840.1.101.3.4.3.40"), // RFC9909,
    HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128(
            "HashSLH-DSA-SHAKE-128s-with-SHAKE128", "2.16.840.1.101.3.4.3.41"), // RFC9909,
    HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128(
            "HashSLH-DSA-SHAKE-128f-with-SHAKE128", "2.16.840.1.101.3.4.3.42"), // RFC9909,
    HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256(
            "HashSLH-DSA-SHAKE-192s-with-SHAKE256", "2.16.840.1.101.3.4.3.43"), // RFC9909,
    HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256(
            "HashSLH-DSA-SHAKE-192f-with-SHAKE256", "2.16.840.1.101.3.4.3.44"), // RFC9909,
    HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256(
            "HashSLH-DSA-SHAKE-256s-with-SHAKE256", "2.16.840.1.101.3.4.3.45"), // RFC9909
    HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256(
            "HashSLH-DSA-SHAKE-256f-with-SHAKE256", "2.16.840.1.101.3.4.3.46"); // RFC9909

    private static final Map<String, X509PublicKeyType> oidMap = new HashMap<>();

    static {
        for (X509PublicKeyType algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final ObjectIdentifier oid;

    X509PublicKeyType(String humanReadableName, String oid) {
        this.humanReadableName = humanReadableName;
        this.oid = new ObjectIdentifier(oid);
    }

    public String getHumanReadableName() {
        return humanReadableName;
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X509PublicKeyType decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }

    public boolean canBeUsedWithSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        if (isSlhDsa()) {
            return signatureAlgorithm == SignatureAlgorithm.SLH_DSA;
        }
        return switch (this) {
            case DH -> false;
            case DSA -> signatureAlgorithm == SignatureAlgorithm.DSA;
            case ECDH_ECDSA -> signatureAlgorithm == SignatureAlgorithm.ECDSA;
            case ECDH_ONLY -> false;
            case ECMQV -> throw new UnsupportedOperationException("Not implemented: " + this);
            case ED25519 -> signatureAlgorithm == SignatureAlgorithm.ED25519;
            case ED448 -> signatureAlgorithm == SignatureAlgorithm.ED448;
            case GOST_R3411_2001, GOST_R3411_94 ->
                    // TODO not sure this is correct
                    signatureAlgorithm == SignatureAlgorithm.GOSTR34102001;
            case GOST_R3411_2012 ->
                    // TODO not sure this is correct
                    signatureAlgorithm == SignatureAlgorithm.GOSTR34102012_256
                            || signatureAlgorithm == SignatureAlgorithm.GOSTR34102012_512;
            case KEA -> throw new UnsupportedOperationException("Not implemented: " + this);
            case RSA -> signatureAlgorithm == SignatureAlgorithm.RSA_PKCS1;
            case RSASSA_PSS -> signatureAlgorithm == SignatureAlgorithm.RSA_SSA_PSS;
            case X25519 -> false;
            case X448 -> false;
            case ML_DSA_44, ML_DSA_65, ML_DSA_87 -> signatureAlgorithm == SignatureAlgorithm.ML_DSA;
            case RSAES_OAEP -> throw new UnsupportedOperationException("Not implemented: " + this);
            default -> throw new UnsupportedOperationException("Not implemented: " + this);
        };
    }

    /**
     * Returns the ML-DSA parameter set this public key type refers to, or null if this is not an
     * ML-DSA public key type.
     */
    public MlDsaParameters getMlDsaParameters() {
        return switch (this) {
            case ML_DSA_44 -> MlDsaParameters.ML_DSA_44;
            case ML_DSA_65 -> MlDsaParameters.ML_DSA_65;
            case ML_DSA_87 -> MlDsaParameters.ML_DSA_87;
            default -> null;
        };
    }

    public boolean isMlDsa() {
        return getMlDsaParameters() != null;
    }

    /**
     * Returns the SLH-DSA parameter set this public key type refers to, or null if this is not an
     * SLH-DSA public key type. The pure and the pre-hash (HashSLH-DSA) OIDs of a parameter set map
     * to the same parameter set.
     */
    public SlhDsaParameters getSlhDsaParameters() {
        return switch (this) {
            case SLH_DSA_SHA2_128S, HASH_SLH_DSA_SHA2_128S_WITH_SHA256 ->
                    SlhDsaParameters.SLH_DSA_SHA2_128S;
            case SLH_DSA_SHA2_128F, HASH_SLH_DSA_SHA2_128F_WITH_SHA256 ->
                    SlhDsaParameters.SLH_DSA_SHA2_128F;
            case SLH_DSA_SHA2_192S, HASH_SLH_DSA_SHA2_192S_WITH_SHA512 ->
                    SlhDsaParameters.SLH_DSA_SHA2_192S;
            case SLH_DSA_SHA2_192F, HASH_SLH_DSA_SHA2_192F_WITH_SHA512 ->
                    SlhDsaParameters.SLH_DSA_SHA2_192F;
            case SLH_DSA_SHA2_256S, HASH_SLH_DSA_SHA2_256S_WITH_SHA512 ->
                    SlhDsaParameters.SLH_DSA_SHA2_256S;
            case SLH_DSA_SHA2_256F, HASH_SLH_DSA_SHA2_256F_WITH_SHA512 ->
                    SlhDsaParameters.SLH_DSA_SHA2_256F;
            case SLH_DSA_SHAKE_128S, HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128 ->
                    SlhDsaParameters.SLH_DSA_SHAKE_128S;
            case SLH_DSA_SHAKE_128F, HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128 ->
                    SlhDsaParameters.SLH_DSA_SHAKE_128F;
            case SLH_DSA_SHAKE_192S, HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256 ->
                    SlhDsaParameters.SLH_DSA_SHAKE_192S;
            case SLH_DSA_SHAKE_192F, HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256 ->
                    SlhDsaParameters.SLH_DSA_SHAKE_192F;
            case SLH_DSA_SHAKE_256S, HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256 ->
                    SlhDsaParameters.SLH_DSA_SHAKE_256S;
            case SLH_DSA_SHAKE_256F, HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256 ->
                    SlhDsaParameters.SLH_DSA_SHAKE_256F;
            default -> null;
        };
    }

    public boolean isSlhDsa() {
        return getSlhDsaParameters() != null;
    }

    public boolean isEc() {
        if (isSlhDsa()) {
            return false;
        }
        return switch (this) {
            case ECDH_ECDSA,
                    ECDH_ONLY,
                    ECMQV,
                    ED25519,
                    ED448,
                    GOST_R3411_2001,
                    GOST_R3411_2012,
                    GOST_R3411_94,
                    X25519,
                    X448 ->
                    true;
            case DH, DSA, KEA, ML_DSA_44, ML_DSA_65, ML_DSA_87, RSA, RSAES_OAEP, RSASSA_PSS ->
                    false;
            default ->
                    throw new UnsupportedOperationException("Not yet implemented: " + this.name());
        };
    }
}
