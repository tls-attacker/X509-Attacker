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
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.TbsCertificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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
        if (chooser.getConfig().isIncludeSerialNumber()) {
            Asn1Integer serialNumber = field.getSerialNumber();
            Asn1PreparatorHelper.prepareField(serialNumber, chooser.getConfig().getSerialNumber());
        }
    }

    private void prepareSignature() {
        field.getSignature().getPreparator(chooser).prepare();
        field.getSignature().getHandler(chooser).adjustContextAfterPrepare();
    }

    private void prepareIssuer() {
        if (chooser.getConfig().isIncludeIssuer()) {
            field.getIssuer().getPreparator(chooser).prepare();
            field.getIssuer().getHandler(chooser).adjustContextAfterPrepare();
        }
    }

    private void prepareValidity() {
        if (chooser.getConfig().isIncludeValidity()) {
            field.getValidity().getPreparator(chooser).prepare();
            field.getValidity().getHandler(chooser).adjustContextAfterPrepare();
        }
    }

    private void prepareSubject() {
        if (chooser.getConfig().isIncludeSubject()) {
            field.getSubject().getPreparator(chooser).prepare();
            field.getSubject().getHandler(chooser).adjustContextAfterPrepare();
        }
    }

    private void prepareSubjectPublicKeyInfo() {
        if (chooser.getConfig().isIncludeSubjectPublicKeyInfo()) {
            field.getSubjectPublicKeyInfo().getPreparator(chooser).prepare();
            field.getSubjectPublicKeyInfo().getHandler(chooser).adjustContextAfterPrepare();
        }
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
            field.getExplicitExtensions().getPreparator(chooser).prepare();
            field.getExplicitExtensions().getHandler(chooser).adjustContextAfterPrepare();
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        if (chooser.getConfig().isIncludeVersion()) {
            children.add(field.getVersion());
        }
        children.add(field.getSerialNumber());
        children.add(field.getSignature());
        if (chooser.getConfig().isIncludeIssuer()) {
            children.add(field.getIssuer());
        }
        children.add(field.getValidity());
        if (chooser.getConfig().isIncludeSubject()) {
            children.add(field.getSubject());
        }
        children.add(field.getSubjectPublicKeyInfo());
        children.add(field.getIssuerUniqueId());
        children.add(field.getSubjectUniqueId());
        children.add(field.getExplicitExtensions());
        if (chooser.getConfig().isAppendUnexpectedCertificateField()) {
            Asn1OctetString octetString = new Asn1OctetString("unexpectedField");
            Asn1PreparatorHelper.prepareField(
                    octetString, new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
            children.add(octetString);
        }

        // Filter null values
        children.removeIf(Objects::isNull);
        return encodeChildren(children);
    }
}
