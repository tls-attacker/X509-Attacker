/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyAlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.*;

public class SubjectPublicKeyAlgorithmIdentifierPreparator
        extends X509ContainerPreparator<SubjectPublicKeyAlgorithmIdentifier> {

    public SubjectPublicKeyAlgorithmIdentifierPreparator(
            X509Chooser chooser,
            SubjectPublicKeyAlgorithmIdentifier subjectPublicKeyAlgorithmIdentifier) {
        super(chooser, subjectPublicKeyAlgorithmIdentifier);
    }

    @Override
    public void prepareSubComponents() {
        Asn1PreparatorHelper.prepareField(
                field.getAlgorithm(), chooser.getConfig().getPublicKeyType().getOid());
        PublicParameters publicKeyParameters = field.getParameters();
        if (publicKeyParameters == null
                && chooser.getConfig().getPublicKeyType() != X509PublicKeyType.RSASSA_PSS) {
            publicKeyParameters = createPublicKeyParameters();
            field.setParameters(publicKeyParameters);
        }
        if (publicKeyParameters != null) {
            publicKeyParameters.getPreparator(chooser).prepare();
            publicKeyParameters.getHandler(chooser).adjustContextAfterPrepare();
            field.setParameters(publicKeyParameters);
        }
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
            case RSA:
                return new X509NullParameters("nullParameters");
            default:
                throw new UnsupportedOperationException("Unnown PublicKeyType: " + publicKeyType);
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        if (field.getParameters() != null) {
            return encodeChildren(field.getAlgorithm(), field.getParameters());
        } else {
            return encodeChildren(field.getAlgorithm());
        }
    }
}
