/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.signatureengine;

public abstract class SignatureEngine {

    private static EngineTuple[] engines = new EngineTuple[] {
        new EngineTuple(Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha1WithRsaEncryptionSignatureEngine.class),
        new EngineTuple(Sha256WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha256WithRsaEncryptionSignatureEngine.class),
        new EngineTuple(Sha512WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha512WithRsaEncryptionSignatureEngine.class),
        new EngineTuple(Md2WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Md2WithRsaEncryptionSignatureEngine.class),
        new EngineTuple(Md4WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Md4WithRsaEncryptionSignatureEngine.class),
        new EngineTuple(Md5WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Md5WithRsaEncryptionSignatureEngine.class),
        new EngineTuple(DsaWithSha1SignatureEngine.objectIdentifierString, DsaWithSha1SignatureEngine.class),
        new EngineTuple(EcDsaWithSha1SignatureEngine.objectIdentifierString, EcDsaWithSha1SignatureEngine.class),
        new EngineTuple(DsaWithSha256SignatureEngine.objectIdentifierString, DsaWithSha256SignatureEngine.class),
        new EngineTuple(EcDsaWithSha256SignatureEngine.objectIdentifierString, EcDsaWithSha256SignatureEngine.class) };

    public static class EngineTuple {

        public final String objectIdentifierString;

        public final Class<? extends SignatureEngine> signatureEngine;

        public EngineTuple(final String objectIdentifierString, final Class<? extends SignatureEngine> signatureEngine) {
            this.objectIdentifierString = objectIdentifierString;
            this.signatureEngine = signatureEngine;
        }
    }

    public enum KeyType {
        RAW_KEY,
        DER_ENCODED,
        PEM_ENCODED
    }

    public static SignatureEngine getInstance(final String objectIdentifierString) throws SignatureEngineException {
        SignatureEngine signatureEngine = null;
        Class<? extends SignatureEngine> signatureEngineClass = findSignatureEngineClass(objectIdentifierString);
        signatureEngine = invoke(signatureEngineClass);
        return signatureEngine;
    }

    private static Class<? extends SignatureEngine> findSignatureEngineClass(final String objectIdentifierString)
        throws SignatureEngineException {
        Class<? extends SignatureEngine> signatureEngineClass = null;
        for (EngineTuple engine : engines) {
            if (engine.objectIdentifierString.equalsIgnoreCase(objectIdentifierString)) {
                signatureEngineClass = engine.signatureEngine;
                break;
            }
        }
        if (signatureEngineClass == null) {
            throw new SignatureEngineException("No signature engine found for [object identifier = "
                + objectIdentifierString + "]!");
        }
        return signatureEngineClass;
    }

    public static SignatureEngine invoke(Class<? extends SignatureEngine> signatureEngineClass)
        throws SignatureEngineException {
        SignatureEngine signatureEngine = null;
        try {
            signatureEngine = signatureEngineClass.newInstance();
        } catch (InstantiationException e) {
            throw new SignatureEngineException(e);
        } catch (IllegalAccessException e) {
            throw new SignatureEngineException(e);
        }
        return signatureEngine;
    }

    /**
     * @return Returns the object identifier associated with the instantiated signature scheme.
     */
    public String retrieveObjectIdentifier() throws SignatureEngineException {
        String result = null;
        for (EngineTuple engineTuple : engines) {
            if (engineTuple.signatureEngine.isInstance(this)) {
                result = engineTuple.objectIdentifierString;
                break;
            }
        }
        if (result == null) {
            throw new SignatureEngineException("Object identifier is not available in SignatureEngine's engine list!");
        }
        return result;
    }

    /**
     * Initializes the signature engine with the corresponding key material.
     *
     * @param keyBytes
     * Bytes of the key material.
     * @param keyType
     * Indicates how the key bytes shall be parsed.
     * @param parameters
     * Binary ASN.1 data from AlgorithmIdentifier's parameter field (see RFC 5280 4.1.1.2).
     */
    public abstract void init(final byte[] keyBytes, final KeyType keyType, final byte[] parameters)
        throws SignatureEngineException;

    /**
     * Signs the given data and returns the signature value. Cannot be called before the signature engine is
     * initialized.
     *
     * @param toBeSigned
     * The data to be signed.
     * @return The signature value.
     */
    public abstract byte[] sign(final byte[] toBeSigned) throws SignatureEngineException;
}
