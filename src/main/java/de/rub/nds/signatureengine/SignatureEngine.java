package de.rub.nds.signatureengine;

import com.sun.xml.internal.ws.api.pipe.Engine;

public abstract class SignatureEngine {

    private static EngineTupel[] engines = new EngineTupel[]{
            new EngineTupel(
                    Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha1WithRsaEncryptionSignatureEngine.class
            ),
            new EngineTupel(
                    Sha512WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha512WithRsaEncryptionSignatureEngine.class
            ),
            new EngineTupel(
                    Md2WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Md2WithRsaEncryptionSignatureEngine.class
            ),
            new EngineTupel(
                    Md4WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Md4WithRsaEncryptionSignatureEngine.class
            ),
            new EngineTupel(
                    Md5WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Md5WithRsaEncryptionSignatureEngine.class
            ),
            new EngineTupel(
                    DsaWithSha1SignatureEngine.objectIdentifierString,
                    DsaWithSha1SignatureEngine.class
            ),
            new EngineTupel(
                    EcDsaWithSha1SignatureEngine.objectIdentifierString,
                    EcDsaWithSha1SignatureEngine.class
            ),
            new EngineTupel(
                    DsaWithSha256SignatureEngine.objectIdentifierString,
                    DsaWithSha256SignatureEngine.class
            )
    };

    public static class EngineTupel {

        public final String objectIdentifierString;

        public final Class<? extends SignatureEngine> signatureEngine;

        public EngineTupel(final String objectIdentifierString, final Class<? extends SignatureEngine> signatureEngine) {
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

    private static Class<? extends SignatureEngine> findSignatureEngineClass(final String objectIdentifierString) throws SignatureEngineException {
        Class<? extends SignatureEngine> signatureEngineClass = null;
        for (EngineTupel engine : engines) {
            if (engine.objectIdentifierString.equalsIgnoreCase(objectIdentifierString)) {
                signatureEngineClass = engine.signatureEngine;
                break;
            }
        }
        if (signatureEngineClass == null) {
            throw new SignatureEngineException("No signature engine found for [object identifier = " + objectIdentifierString + "]!");
        }
        return signatureEngineClass;
    }

    public static SignatureEngine invoke(Class<? extends SignatureEngine> signatureEngineClass) throws SignatureEngineException {
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
        for (EngineTupel engineTupel : engines) {
            if (engineTupel.signatureEngine.isInstance(this)) {
                result = engineTupel.objectIdentifierString;
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
     * @param keyBytes   Bytes of the key material.
     * @param keyType    Indicates how the key bytes shall be parsed.
     * @param parameters Binary ASN.1 data from AlgorithmIdentifier's parameter field (see RFC 5280 4.1.1.2).
     */
    public abstract void init(final byte[] keyBytes, final KeyType keyType, final byte[] parameters) throws SignatureEngineException;

    /**
     * Signs the given data and returns the signature value. Cannot be called before the signature engine is initialized.
     *
     * @param toBeSigned The data to be signed.
     * @return The signature value.
     */
    public abstract byte[] sign(final byte[] toBeSigned) throws SignatureEngineException;
}
