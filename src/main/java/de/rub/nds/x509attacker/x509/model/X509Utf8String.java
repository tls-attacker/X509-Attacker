/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.EmptyHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509ComponentFieldParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.BufferedInputStream;

/** Wrapper for Asn1Utf8String to implement X509Component */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Utf8String extends Asn1Utf8String implements X509Component {

    private X509Utf8String() {
        super(null);
    }

    public X509Utf8String(String identifier) {
        super(identifier);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler<>(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509ComponentFieldParser<X509Utf8String>(chooser, this) {
            @Override
            protected void parseContent(BufferedInputStream inputStream) {
                // Content is already parsed in the parent class
            }
        };
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509Asn1FieldPreparator<X509Utf8String>(chooser, this) {
            @Override
            protected byte[] encodeContent() {
                if (field.getValue() != null) {
                    Asn1PreparatorHelper.prepareField(field, field.getValue().getValue());
                }
                return field.getContent().getOriginalValue();
            }
        };
    }
}
