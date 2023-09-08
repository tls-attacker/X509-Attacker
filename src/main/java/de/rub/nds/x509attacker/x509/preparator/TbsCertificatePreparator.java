/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.TbsCertificate;
import java.util.ArrayList;
import java.util.List;
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
        Asn1PreparatorHelper.prepareField(serialNumber, chooser.getConfig().getSerialNumber());
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
            Asn1PreparatorHelper.prepareField(
                    field.getIssuerUniqueId(), chooser.getIssuerUniqueId(), (byte) 0);
        }
    }

    private void prepareSubjectUniqueId() {
        // SubjectUniqueID is an optional field
        if (chooser.getConfig().isIncludeSubjectUniqueId()) {
            Asn1PreparatorHelper.prepareField(
                    field.getSubjectUniqueId(), chooser.getConfig().getSubjectUniqueId(), (byte) 0);
        }
    }

    private void prepareExtensions() {
        if (chooser.getConfig().isIncludeExtensions()) {
            LOGGER.warn("Extensions not supported yet");
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getVersion());
        children.add(field.getSerialNumber());
        children.add(field.getSignature());
        children.add(field.getIssuer());
        children.add(field.getValidity());
        children.add(field.getSubject());
        children.add(field.getSubjectPublicKeyInfo());
        children.add(field.getIssuerUniqueId());
        children.add(field.getSubjectUniqueId());
        children.add(field.getExplicitExtensions());
        // Filter null values
        children.removeIf(child -> child == null);
        return encodeChildren(children);
    }
}
