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
import de.rub.nds.x509attacker.x509.model.CertificateSignatureAlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509NullParameters;

public class CertificateSignatureAlgorithmIdentifierPreparator
        extends X509ContainerPreparator<CertificateSignatureAlgorithmIdentifier> {

    public CertificateSignatureAlgorithmIdentifierPreparator(
            X509Chooser chooser,
            CertificateSignatureAlgorithmIdentifier certificateSignatureAlgorithmIdentifier) {
        super(chooser, certificateSignatureAlgorithmIdentifier);
    }

    @Override
    public void prepareSubComponents() {
        Asn1PreparatorHelper.prepareField(
                field.getAlgorithm(), chooser.getSignatureAlgorithm().getOid());
        PublicParameters signatureParameters = field.getParameters();
        if (signatureParameters == null) {
            signatureParameters = createSignatureParameters();
            field.setParameters(signatureParameters);
        }
        signatureParameters.getPreparator(chooser).prepare();
        signatureParameters.getHandler(chooser).adjustContextAfterPrepare();
        field.setParameters(signatureParameters);
    }

    private PublicParameters createSignatureParameters() {
        X509PublicKeyType publicKeyType = chooser.getIssuerPublicKeyType();
        return switch (publicKeyType) {
            case DH -> new X509DhParameters("dhParameters", chooser.getConfig());
            case DSA -> new X509DssParameters("dssParameters");
            case ECDH_ECDSA -> new X509EcNamedCurveParameters("ecNamedCurve");
            case RSA -> new X509NullParameters("nullParameters");
            default -> throw new UnsupportedOperationException("Unknown PublicKeyType: " + publicKeyType);
        };
    }

    @Override
    public byte[] encodeChildrenContent() {
        if (chooser.getConfig().isIncludeSignatureAlgorithm()) {
            if (field.getParameters() != null) {
                return encodeChildren(field.getAlgorithm(), field.getParameters());
            } else {
                return encodeChildren(field.getAlgorithm());
            }
        } else {
            return new byte[] {};
        }
    }
}
