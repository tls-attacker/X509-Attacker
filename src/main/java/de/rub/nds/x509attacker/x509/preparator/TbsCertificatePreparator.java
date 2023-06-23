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
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.model.TbsCertificate;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TbsCertificatePreparator extends X509ContainerPreparator<TbsCertificate> {

    private static final Logger LOGGER = LogManager.getLogger();

    public TbsCertificatePreparator(X509Chooser chooser, TbsCertificate tbsCertificate) {
        super(chooser, tbsCertificate);
    }

    @Override
    public void prepareSubComponents() {
        prepareVersion();
        prepareSerialNumber();
        prepareSignature();
        prepareIssuer();
        prepareValidity();
        prepareSubject();
        prepareSubjectPublicKeyInfo();
        prepareIssuerUniqueId();
        prepareSubjectUniqueId();
        prepareExtensions();
    }

    private void prepareVersion() {
        field.getVersion().getPreparator(chooser).prepare();
    }

    private void prepareSerialNumber() {
        Asn1Integer serialNumber = field.getSerialNumber();
        prepareField(serialNumber, chooser.getConfig().getSerialNumber());
    }

    private void prepareSignature() {
        field.getSignature().getPreparator(chooser).prepare();
    }

    private void prepareIssuer() {
        field.getIssuer().getPreparator(chooser).prepare();
    }

    private void prepareValidity() {
        field.getValidity().getPreparator(chooser).prepare();
    }

    private void prepareSubject() {
        field.getSubject().getPreparator(chooser).prepare();
    }

    private void prepareSubjectPublicKeyInfo() {
        SubjectPublicKeyInfo subjectPublicKeyInfo = field.getSubjectPublicKeyInfo();
        AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        algorithm
                .getAlgorithm()
                .setValue(chooser.getConfig().getPublicKeyType().getOid().toString());
        algorithm
                .getParameters()
                .setIdentifier(chooser.getConfig().getPublicKeyType().getOid().toString());
        algorithm.getAlgorithm().getPreparator(chooser).prepare();
        prepareField(algorithm.getAlgorithm(), chooser.getConfig().getPublicKeyType().getOid());
        prepareField(algorithm.getParameters());
        PublicParameters publicKeyParameters = createPublicKeyParameters();
        if (publicKeyParameters == null) {
            algorithm.instantiateParameters(new Asn1Null("parameters"));
        } else if (publicKeyParameters instanceof Asn1Field) {
            algorithm.instantiateParameters((Asn1Field) publicKeyParameters);
        } else {
            throw new RuntimeException("Signature Parameters are not an ASN.1 Field");
        }
        algorithm.getParameters().getPreparator(chooser).prepare();
        subjectPublicKeyInfo.getSubjectPublicKeyBitString().getPreparator(chooser).prepare();
        subjectPublicKeyInfo.getPreparator(chooser).prepare();
    }

    private void prepareIssuerUniqueId() {
        // IssuerUniqueID is an optional field
        if (chooser.getConfig().isIncludeIssuerUniqueId()) {
            prepareField(field.getIssuerUniqueId(), chooser.getIssuerUniqueId(), (byte) 0);
            field.addChild(field.getIssuerUniqueId());
        }
    }

    private void prepareSubjectUniqueId() {
        // SubjectUniqueID is an optional field
        if (chooser.getConfig().isIncludeSubjectUniqueId()) {
            prepareField(field.getSubjectUniqueId(), chooser.getSubjectUniqueId(), (byte) 0);
            field.addChild(field.getSubjectUniqueId());
        }
    }

    private void prepareExtensions() {
        if (chooser.getConfig().isIncludeExtensions()) {
            LOGGER.warn("Extensions not supported yet");
        }
    }
}
