/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyAlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;

public class SubjectPublicKeyAlgorithmIdentifierPreparator
        extends X509ContainerPreparator<SubjectPublicKeyAlgorithmIdentifier> {

    public SubjectPublicKeyAlgorithmIdentifierPreparator(
            X509Chooser chooser,
            SubjectPublicKeyAlgorithmIdentifier subjectPublicKeyAlgorithmIdentifier) {
        super(chooser, subjectPublicKeyAlgorithmIdentifier);
    }

    @Override
    public void prepareSubComponents() {
        throw new UnsupportedOperationException("Unimplemented method 'prepareSubComponents'");
    }

    private PublicParameters createPublicKeyParameters() {
        X509PublicKeyType publicKeyType = chooser.getConfig().getPublicKeyType();
        switch (publicKeyType) {
            case DH:
                return new X509DhParameters("dhParameters", chooser.getConfig());
            case DSA:
                return new X509DssParameters("dssParameters");
            case ECDH_ECDSA:
                return new X509EcNamedCurveParameters("ecNamedCurve");
            default:
                return null;
        }
    }
}
