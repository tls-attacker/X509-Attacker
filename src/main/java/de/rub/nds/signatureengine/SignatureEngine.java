package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.KeyType;
import java.util.LinkedList;
import java.util.List;

public abstract class SignatureEngine {

    public final static EngineTupel[] engines = new EngineTupel[]{
            new EngineTupel(
                    Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha1WithRsaEncryptionSignatureEngine.class,
                    Sha1WithRsaEncryptionSignatureEngine.name,
                    Sha1WithRsaEncryptionSignatureEngine.keyType                    
            ),
            new EngineTupel(
                    Sha224WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha224WithRsaEncryptionSignatureEngine.class,
                    Sha224WithRsaEncryptionSignatureEngine.name,
                    Sha224WithRsaEncryptionSignatureEngine.keyType 
            ),
            new EngineTupel(
                    Sha256WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha256WithRsaEncryptionSignatureEngine.class,
                    Sha256WithRsaEncryptionSignatureEngine.name,
                    Sha256WithRsaEncryptionSignatureEngine.keyType 
            ),
            new EngineTupel(
                    Sha384WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha384WithRsaEncryptionSignatureEngine.class,
                    Sha384WithRsaEncryptionSignatureEngine.name,
                    Sha384WithRsaEncryptionSignatureEngine.keyType 
            ),
            new EngineTupel(
                    Sha512WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Sha512WithRsaEncryptionSignatureEngine.class,
                    Sha512WithRsaEncryptionSignatureEngine.name,
                    Sha512WithRsaEncryptionSignatureEngine.keyType 
            ),
            new EngineTupel(
                    Md2WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Md2WithRsaEncryptionSignatureEngine.class,
                    Md2WithRsaEncryptionSignatureEngine.name,
                    Md2WithRsaEncryptionSignatureEngine.keyType 
            ),
//            new EngineTupel(
//                    Md4WithRsaEncryptionSignatureEngine.objectIdentifierString,
//                    Md4WithRsaEncryptionSignatureEngine.class,
//                    Md4WithRsaEncryptionSignatureEngine.name,
//                    Md4WithRsaEncryptionSignatureEngine.keyType 
//            ),
            new EngineTupel(
                    Md5WithRsaEncryptionSignatureEngine.objectIdentifierString,
                    Md5WithRsaEncryptionSignatureEngine.class,
                    Md5WithRsaEncryptionSignatureEngine.name,
                    Md5WithRsaEncryptionSignatureEngine.keyType 
            ),
            new EngineTupel(
                    DsaWithSha1SignatureEngine.objectIdentifierString,
                    DsaWithSha1SignatureEngine.class,
                    DsaWithSha1SignatureEngine.name,
                    DsaWithSha1SignatureEngine.keyType 
            ),
            new EngineTupel(
                    EcdsaWithSha1SignatureEngine.objectIdentifierString,
                    EcdsaWithSha1SignatureEngine.class,
                    EcdsaWithSha1SignatureEngine.name,
                    EcdsaWithSha1SignatureEngine.keyType 
            )
    };

    public static class EngineTupel {

        public final String objectIdentifierString;

        public final Class<? extends SignatureEngine> signatureEngine;
        
        public final String name;
        
        public final KeyType keyType;

        public EngineTupel(final String objectIdentifierString, final Class<? extends SignatureEngine> signatureEngine, final String name, final KeyType keyType) {
            this.objectIdentifierString = objectIdentifierString;
            this.signatureEngine = signatureEngine;
            this.name = name;
            this.keyType = keyType;
        }
    }
    
    public static EngineTupel getEngineTupelForOID(final String signOID) {
        for (EngineTupel engine : engines) {
            if (engine.objectIdentifierString.equalsIgnoreCase(signOID)) {
                return engine;
            }
        }
        return null;
    }
    
    public static List<EngineTupel> getEngineTupelForKeyType(final KeyType keyType) {
        List<EngineTupel> listOfCompatibleEngines = new LinkedList<>();
        for (EngineTupel engine : engines) {
            if (engine.keyType.equals(keyType)) {
                listOfCompatibleEngines.add(engine);
            }
        }
        return listOfCompatibleEngines;
    }

    public enum KeyFormat {
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
     * @param keyFormat    Indicates how the key bytes shall be parsed.
     * @param parameters Binary ASN.1 data from AlgorithmIdentifier's parameter field (see RFC 5280 4.1.1.2).
     */
    public abstract void init(final byte[] keyBytes, final KeyFormat keyFormat, final byte[] parameters) throws SignatureEngineException;

    /**
     * Signs the given data and returns the signature value. Cannot be called before the signature engine is initialized.
     *
     * @param toBeSigned The data to be signed.
     * @return The signature value.
     */
    public abstract byte[] sign(final byte[] toBeSigned) throws SignatureEngineException;
}
