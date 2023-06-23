/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.model.CertificateSignatureAlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;

public class CertificateSignatureAlgorithmIdentifierPreparator
        extends X509ContainerPreparator<CertificateSignatureAlgorithmIdentifier> {

    public CertificateSignatureAlgorithmIdentifierPreparator(
            X509Chooser chooser,
            CertificateSignatureAlgorithmIdentifier certificateSignatureAlgorithmIdentifier) {
        super(chooser, certificateSignatureAlgorithmIdentifier);
    }

    @Override
    public void prepareSubComponents() {
        prepareField(field.getAlgorithm(), chooser.getSignatureAlgorithm().getOid());
        PublicParameters signatureParameters = createSignatureParameters();
        if (signatureParameters == null) {
            field.setParameters(new Asn1Null("parameters"));
        } else if (signatureParameters instanceof Asn1Field) {
            field.setParameters((Asn1Field) signatureParameters);
        } else {
            throw new RuntimeException("Signature Parameters are not an ASN.1 Field");
        }
    }

    private PublicParameters createSignatureParameters() {
        X509PublicKeyType publicKeyType = chooser.getIssuerPublicKeyType();
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
