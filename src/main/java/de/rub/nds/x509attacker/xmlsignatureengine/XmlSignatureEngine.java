/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.xmlsignatureengine;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.util.AttributeParser;
import de.rub.nds.signatureengine.SignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.util.ByteArrayUtils;
import de.rub.nds.x509attacker.X509Attributes;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.linker.Linker;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public final class XmlSignatureEngine {

    private final Linker linker;

    private final Map<String, Asn1Encodable> identifierMap;

    private final List<SignatureInfo> signatureInfoList = new LinkedList<>();
    private KeyType keyType;

    public XmlSignatureEngine(final Linker linker, final Map<String, Asn1Encodable> identifierMap) {
        this.linker = linker;
        this.identifierMap = identifierMap;
        this.scanForSignatureInfoObjects();
    }

    public void scanForSignatureInfoObjects() {
        List<Asn1Encodable> xmlObjects = new LinkedList<>(this.identifierMap.values());
        this.signatureInfoList.clear();
        for (Asn1Encodable xmlObject : xmlObjects) {
            if (xmlObject instanceof SignatureInfo) {
                this.signatureInfoList.add((SignatureInfo) xmlObject);
            }
        }
    }

    public void computeSignatures() throws XmlSignatureEngineException {
        for (SignatureInfo signatureInfo : this.signatureInfoList) {
            this.computeSignature(signatureInfo);
        }
    }

    public void computeSignature(KeyInfo keyInfo) throws XmlSignatureEngineException {
        if (signatureInfoList.size() == 1) {
            this.computeSignature(signatureInfoList.get(0), keyInfo);
        } else {
            throw new XmlSignatureEngineException("computeSignature(KeyInfo) only works with one SignatureInfoObject");
        }
    }

    private void computeSignature(final SignatureInfo signatureInfo) throws XmlSignatureEngineException {
        byte[] keyBytes = this.getKey(signatureInfo);
        this.computeSignature(signatureInfo, keyBytes);
    }

    private void computeSignature(final SignatureInfo signatureInfo, KeyInfo keyInfo)
        throws XmlSignatureEngineException {
        byte[] keyBytes = this.getKey(keyInfo);
        this.computeSignature(signatureInfo, keyBytes);
    }

    private void computeSignature(final SignatureInfo signatureInfo, byte[] keyBytes)
        throws XmlSignatureEngineException {
        try {
            byte[] toBeSigned = this.prepareForSigning(signatureInfo);
            String objectIdentifierValue = this.getSignatureAlgorithmObjectIdentifierValue(signatureInfo);
            byte[] signatureAlgorithmParameters = this.getSignatureAlgorithmParameters(signatureInfo);
            SignatureEngine signatureEngine = SignatureEngine.getInstance(objectIdentifierValue);
            signatureEngine.init(keyBytes, SignatureEngine.KeyFormat.PEM_ENCODED, signatureAlgorithmParameters);
            byte[] signatureValue = signatureEngine.sign(toBeSigned);
            this.writeSignatureValueToTarget(signatureInfo, signatureValue);
        } catch (SignatureEngineException e) {
            throw new XmlSignatureEngineException(e);
        }
    }

    private byte[] prepareForSigning(final SignatureInfo signatureInfo) {
        byte[] toBeSigned = new byte[0];
        try {
            for (String toBeSignedIdentifier : signatureInfo.getToBeSignedIdentifiers()) {
                Asn1Encodable toBeSignedEncodable = this.identifierMap.get(toBeSignedIdentifier.trim());
                byte[] encodedForSignature = Asn1EncoderForX509.encodeForSignature(this.linker, toBeSignedEncodable);
                toBeSigned = ByteArrayUtils.merge(toBeSigned, encodedForSignature);
            }
        } catch (NullPointerException e) {
            throw new XmlSignatureEngineException("Did you specify an identifier that cannot be resolved?", e);
        } catch (Throwable e) {
            throw new XmlSignatureEngineException(e);
        }
        return toBeSigned;
    }

    /* gets KeyBytes from KeyInfo Object described in the signatureInfo */
    private byte[] getKey(final SignatureInfo signatureInfo) {
        byte[] key = null;
        Asn1Encodable linkedKeyInfo = this.identifierMap.get(signatureInfo.getKeyInfoIdentifier().trim());
        if (linkedKeyInfo != null && linkedKeyInfo instanceof KeyInfo) {
            KeyInfo keyInfo = (KeyInfo) linkedKeyInfo;

            key = getKey(keyInfo);

        } else {
            throw new XmlSignatureEngineException(
                "SignatureInfo does not contain the mandatory KeyInfoIdentifier element or KeyInfoIdentifier links to an element of type other than KeyInfo!");
        }
        return key;
    }

    /* gets KeyBytes from KeyInfo Object */
    private byte[] getKey(final KeyInfo keyInfo) {
        byte[] keyBytes = null;
        try {
            keyBytes = keyInfo.getKeyBytes();
            if (keyBytes == null) {
                String keyFile = this.getKeyFileName(keyInfo);
                keyBytes = KeyFileManager.getReference().getKeyFileContent(keyFile);
            }
        } catch (KeyFileManagerException e) {
            throw new XmlSignatureEngineException(e);
        }
        keyType = keyInfo.getKeyType();
        return keyBytes;
    }

    private String getKeyFileName(final KeyInfo keyInfo) {
        String keyFile = keyInfo.getKeyFileName();
        if (keyFile == null || keyFile.isEmpty()) {
            String identifier =
                AttributeParser.parseStringAttributeOrDefault(keyInfo, X509Attributes.FROM_IDENTIFIER, null);
            Asn1Encodable asn1Encodable = this.identifierMap.get(identifier);
            if (asn1Encodable instanceof KeyInfo) {
                keyFile = this.getKeyFileName((KeyInfo) asn1Encodable);
            } else {
                throw new XmlSignatureEngineException(
                    "KeyInfo uses fromIdentifier to reference an element that is not of type KeyInfo!");
            }
        }
        return keyFile.trim();
    }

    private String getSignatureAlgorithmObjectIdentifierValue(final SignatureInfo signatureInfo) {
        String objectIdentifierValue = signatureInfo.getSignatureAlgorithmOidValue();
        if (objectIdentifierValue == null || objectIdentifierValue.isEmpty()) {
            try {
                Asn1ObjectIdentifier asn1ObjectIdentifier = (Asn1ObjectIdentifier) this.identifierMap
                    .get(signatureInfo.getSignatureAlgorithmOidIdentifier().trim());
                objectIdentifierValue = asn1ObjectIdentifier.getValue();
            } catch (Throwable e) {
                throw new XmlSignatureEngineException(
                    "SignatureInfo must contain either signatureAlgorithmOidValue or signatureAlgorithmOidIdentifier whereas signatureAlgorithmOidIdentifier needs to contain an identifier pointing to Asn1ObjectIdentifier!");
            }
        }
        return objectIdentifierValue.trim();
    }

    private byte[] getSignatureAlgorithmParameters(final SignatureInfo signatureInfo) {
        byte[] parameters = null;
        String parametersIdentifier = signatureInfo.getParametersIdentifier().trim();
        Asn1Encodable asn1Parameters = signatureInfo.getParameters();
        if (parametersIdentifier != null && parametersIdentifier.isEmpty() == false) {
            asn1Parameters = this.identifierMap.get(parametersIdentifier);
        }
        if (asn1Parameters != null) {
            parameters = Asn1EncoderForX509.encode(this.linker, asn1Parameters);
        }
        return parameters;
    }

    private void writeSignatureValueToTarget(final SignatureInfo signatureInfo, final byte[] signatureValue) {
        String targetIdentifier = signatureInfo.getSignatureValueTargetIdentifier().trim();
        Asn1Encodable targetEncodable = this.identifierMap.get(targetIdentifier);
        this.writeSignatureValueToTargetEncodable(targetEncodable, signatureValue);
    }

    private void writeSignatureValueToTargetEncodable(final Asn1Encodable targetEncodable,
        final byte[] signatureValue) {
        if (targetEncodable instanceof Asn1PrimitiveBitString) {
            Asn1PrimitiveBitString targetBitString = (Asn1PrimitiveBitString) targetEncodable;
            targetBitString.setValue(signatureValue);
        } else if (targetEncodable instanceof Asn1PrimitiveOctetString) {
            Asn1PrimitiveOctetString targetOctetString = (Asn1PrimitiveOctetString) targetEncodable;
            targetOctetString.setValue(signatureValue);
        } else {
            throw new XmlSignatureEngineException(
                "Signature value can only be written to ASN.1 types Asn1PrimitiveBitString and Asn1PrimitiveOctetString!");
        }
    }
}
