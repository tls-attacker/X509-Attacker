/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;

/**
 *
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
 * subjectPublicKey BIT STRING }
 *
 */
public class SubjectPublicKeyInfo extends Asn1Sequence {

    @HoldsModifiableVariable
    private AlgorithmIdentifier algorithm;

    @HoldsModifiableVariable
    private Asn1EncapsulatingBitString subjectPublicKey;

    public SubjectPublicKeyInfo(String identifier) {
        super(identifier);
        algorithm = new AlgorithmIdentifier("algorithm");
        subjectPublicKey = new Asn1EncapsulatingBitString("subjectPublicKey");
        addChild(algorithm);
        addChild(subjectPublicKey);
    }

    public AlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(AlgorithmIdentifier algorithm) {
        this.algorithm = algorithm;
    }

    public Asn1EncapsulatingBitString getSubjectPublicKey() {
        return subjectPublicKey;
    }

    public void setSubjectPublicKey(Asn1EncapsulatingBitString subjectPublicKey) {
        this.subjectPublicKey = subjectPublicKey;
    }

}
