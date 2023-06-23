/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.TbsCertificate;
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
        field.getSubjectPublicKeyInfo().getPreparator(chooser).prepare();
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
            prepareField(
                    field.getSubjectUniqueId(), chooser.getConfig().getSubjectUniqueId(), (byte) 0);
            field.addChild(field.getSubjectUniqueId());
        }
    }

    private void prepareExtensions() {
        if (chooser.getConfig().isIncludeExtensions()) {
            LOGGER.warn("Extensions not supported yet");
        }
    }
}
