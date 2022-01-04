/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.KeyType;
import java.util.LinkedList;
import java.util.List;

public abstract class SignatureEngine {

    public final static EngineTuple[] engines = new EngineTuple[] {
        new EngineTuple(Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha1WithRsaEncryptionSignatureEngine.class, Sha1WithRsaEncryptionSignatureEngine.name,
            Sha1WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(Sha224WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha224WithRsaEncryptionSignatureEngine.class, Sha224WithRsaEncryptionSignatureEngine.name,
            Sha224WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(Sha256WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha256WithRsaEncryptionSignatureEngine.class, Sha256WithRsaEncryptionSignatureEngine.name,
            Sha256WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(Sha384WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha384WithRsaEncryptionSignatureEngine.class, Sha384WithRsaEncryptionSignatureEngine.name,
            Sha384WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(Sha512WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Sha512WithRsaEncryptionSignatureEngine.class, Sha512WithRsaEncryptionSignatureEngine.name,
            Sha512WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(Md2WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Md2WithRsaEncryptionSignatureEngine.class, Md2WithRsaEncryptionSignatureEngine.name,
            Md2WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(Md5WithRsaEncryptionSignatureEngine.objectIdentifierString,
            Md5WithRsaEncryptionSignatureEngine.class, Md5WithRsaEncryptionSignatureEngine.name,
            Md5WithRsaEncryptionSignatureEngine.keyType),
        new EngineTuple(DsaWithSha1SignatureEngine.objectIdentifierString, DsaWithSha1SignatureEngine.class,
            DsaWithSha1SignatureEngine.name, DsaWithSha1SignatureEngine.keyType),
        new EngineTuple(DsaWithSha224SignatureEngine.objectIdentifierString, DsaWithSha224SignatureEngine.class,
            DsaWithSha224SignatureEngine.name, DsaWithSha224SignatureEngine.keyType),
        new EngineTuple(DsaWithSha256SignatureEngine.objectIdentifierString, DsaWithSha256SignatureEngine.class,
            DsaWithSha256SignatureEngine.name, DsaWithSha256SignatureEngine.keyType),
        new EngineTuple(DsaWithSha384SignatureEngine.objectIdentifierString, DsaWithSha384SignatureEngine.class,
            DsaWithSha384SignatureEngine.name, DsaWithSha384SignatureEngine.keyType),
        new EngineTuple(DsaWithSha512SignatureEngine.objectIdentifierString, DsaWithSha512SignatureEngine.class,
            DsaWithSha512SignatureEngine.name, DsaWithSha512SignatureEngine.keyType),
        new EngineTuple(EcdsaWithSha1SignatureEngine.objectIdentifierString, EcdsaWithSha1SignatureEngine.class,
            EcdsaWithSha1SignatureEngine.name, EcdsaWithSha1SignatureEngine.keyType),
        new EngineTuple(EcdsaWithSha224SignatureEngine.objectIdentifierString, EcdsaWithSha224SignatureEngine.class,
            EcdsaWithSha224SignatureEngine.name, EcdsaWithSha224SignatureEngine.keyType),
        new EngineTuple(EcdsaWithSha256SignatureEngine.objectIdentifierString, EcdsaWithSha256SignatureEngine.class,
            EcdsaWithSha256SignatureEngine.name, EcdsaWithSha256SignatureEngine.keyType),
        new EngineTuple(EcdsaWithSha384SignatureEngine.objectIdentifierString, EcdsaWithSha384SignatureEngine.class,
            EcdsaWithSha384SignatureEngine.name, EcdsaWithSha384SignatureEngine.keyType),
        new EngineTuple(EcdsaWithSha512SignatureEngine.objectIdentifierString, EcdsaWithSha512SignatureEngine.class,
            EcdsaWithSha512SignatureEngine.name, EcdsaWithSha512SignatureEngine.keyType) };

    public static EngineTuple getEngineTupelForOID(final String signOID) {
        for (EngineTuple engine : engines) {
            if (engine.getObjectIdentifierString().equalsIgnoreCase(signOID)) {
                return engine;
            }
        }
        return null;
    }

    public static List<EngineTuple> getEngineTupelForKeyType(final KeyType keyType) {
        List<EngineTuple> listOfCompatibleEngines = new LinkedList<>();
        for (EngineTuple engine : engines) {
            if (engine.getKeyType().equals(keyType)) {
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
        SignatureEngine signatureEngine;
        Class<? extends SignatureEngine> signatureEngineClass = findSignatureEngineClass(objectIdentifierString);
        signatureEngine = invoke(signatureEngineClass);
        return signatureEngine;
    }

    private static Class<? extends SignatureEngine> findSignatureEngineClass(final String objectIdentifierString)
        throws SignatureEngineException {
        Class<? extends SignatureEngine> signatureEngineClass = null;
        for (EngineTuple engine : engines) {
            if (engine.getObjectIdentifierString().equalsIgnoreCase(objectIdentifierString)) {
                signatureEngineClass = engine.getSignatureEngine();
                break;
            }
        }
        if (signatureEngineClass == null) {
            throw new SignatureEngineException(
                "No signature engine found for [object identifier = " + objectIdentifierString + "]!");
        }
        return signatureEngineClass;
    }

    public static SignatureEngine invoke(Class<? extends SignatureEngine> signatureEngineClass)
        throws SignatureEngineException {
        SignatureEngine signatureEngine = null;
        try {
            signatureEngine = signatureEngineClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new SignatureEngineException(e);
        }
        return signatureEngine;
    }

    /**
     * @return                                                     Returns the object identifier associated with the
     *                                                             instantiated signature scheme.
     * @throws de.rub.nds.signatureengine.SignatureEngineException
     *                                                             when the EngineTuple cannot be found
     */
    public String retrieveObjectIdentifier() throws SignatureEngineException {
        String result = null;
        for (EngineTuple engineTuple : engines) {
            if (engineTuple.getSignatureEngine().isInstance(this)) {
                result = engineTuple.getObjectIdentifierString();
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
     * @param  keyBytes
     *                                                             Bytes of the key material.
     * @param  keyFormat
     *                                                             Indicates how the key bytes shall be parsed.
     * @param  parameters
     *                                                             Binary ASN.1 data from AlgorithmIdentifier's
     *                                                             parameter field (see RFC 5280 4.1.1.2).
     * @throws de.rub.nds.signatureengine.SignatureEngineException
     *                                                             when the initialisation fails
     */
    public abstract void init(final byte[] keyBytes, final KeyFormat keyFormat, final byte[] parameters)
        throws SignatureEngineException;

    /**
     * Signs the given data and returns the signature value.Cannot be called before the signature engine is initialized.
     *
     * @param  toBeSigned
     *                                                             The data to be signed.
     * @return                                                     The signature value.
     * @throws de.rub.nds.signatureengine.SignatureEngineException
     *                                                             when the signing fails
     */
    public abstract byte[] sign(final byte[] toBeSigned) throws SignatureEngineException;

}
