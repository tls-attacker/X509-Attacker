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

/**
 *
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
 *
 */
public class SubjectPublicKeyInfo extends Asn1Sequence {

    public AlgorithmIdentifier algorithm;
    public Asn1EncapsulatingBitString subjectPublicKey;

    public SubjectPublicKeyInfo(String identifier) {
        this.setIdentifier(identifier);
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
