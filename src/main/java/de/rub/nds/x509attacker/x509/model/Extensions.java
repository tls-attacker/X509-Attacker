/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.ExtensionsHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.ExtensionsParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.ExtensionsPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

/** Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Extensions extends Asn1Sequence implements X509Component {

    private List<Extension> extensionList;

    private Extensions() {
        super(null);
        extensionList = new ArrayList<>();
    }

    public Extensions(String identifier) {
        super(identifier);
        extensionList = new ArrayList<>();
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new ExtensionsHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new ExtensionsParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new ExtensionsPreparator(chooser, this);
    }

    public List<Extension> getExtensionList() {
        return extensionList;
    }

    public void setExtensionList(List<Extension> extensionList) {
        this.extensionList = extensionList;
    }

    public void addExtension(Extension extension) {
        this.extensionList.add(extension);
    }
}
