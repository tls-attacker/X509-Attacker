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
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.signatureengine.SignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.SignatureEngineFactory;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.util.ByteArrayUtils;
import de.rub.nds.x509attacker.linker.Linker;
import java.security.PrivateKey;
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

    public void computeSignature(final SignatureInfo signatureInfo, PrivateKey privateKey) {
        try {
            byte[] toBeSigned = this.prepareForSigning(signatureInfo);
            String objectIdentifierValue = this.getSignatureAlgorithmObjectIdentifierValue(signatureInfo);
            SignatureEngine signatureEngine = SignatureEngineFactory.getEngineForOid(objectIdentifierValue);
            byte[] signatureValue = signatureEngine.sign(privateKey, toBeSigned);
            this.writeSignatureValueToTarget(signatureInfo, signatureValue);
        } catch (SignatureEngineException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] prepareForSigning(final SignatureInfo signatureInfo) {
        byte[] toBeSigned = new byte[0];
        for (String toBeSignedIdentifier : signatureInfo.getToBeSignedIdentifiers()) {
            Asn1Encodable toBeSignedEncodable = this.identifierMap.get(toBeSignedIdentifier.trim());
            byte[] encodedForSignature = Asn1EncoderForX509.encodeForSignature(this.linker, toBeSignedEncodable);
            toBeSigned = ByteArrayUtils.merge(toBeSigned, encodedForSignature);
        }
        return toBeSigned;
    }

    private String getSignatureAlgorithmObjectIdentifierValue(final SignatureInfo signatureInfo) {
        String objectIdentifierValue = signatureInfo.getSignatureAlgorithmOidValue();
        if (objectIdentifierValue == null || objectIdentifierValue.isEmpty()) {
            try {
                Asn1ObjectIdentifier asn1ObjectIdentifier = (Asn1ObjectIdentifier) this.identifierMap
                    .get(signatureInfo.getSignatureAlgorithmOidIdentifier().trim());
                objectIdentifierValue = asn1ObjectIdentifier.getValue();
            } catch (Throwable e) {
                throw new RuntimeException(
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
            throw new RuntimeException(
                "Signature value can only be written to ASN.1 types Asn1PrimitiveBitString and Asn1PrimitiveOctetString!");
        }
    }
}
