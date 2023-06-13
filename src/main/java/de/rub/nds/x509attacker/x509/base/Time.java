/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import org.joda.time.DateTime;

import de.rub.nds.asn1.exceptions.NotInitializedException;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1GeneralizedTime;
import de.rub.nds.asn1.model.Asn1UtcTime;
import de.rub.nds.asn1.time.TimeDecoder;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Time extends Asn1Field implements X509Component {

    private Time() {
        super(null);
    }

    public Time(String identifier) {
        super(identifier, new Asn1UtcTime("utcTime"), new Asn1GeneralizedTime("generalizedTime"));
    }

    public DateTime getTimeValue() {
        Asn1Field choice = getSelectedChoice();
        if (choice == null) {
            throw new NotInitializedException(
                    "Not initialized. Prepare or parse it first to access values");
        }
        if (choice instanceof Asn1UtcTime) {
            String utcString = ((Asn1UtcTime) choice).getValue().getValue();
            return TimeDecoder.decodeUtc(utcString);
        } else if (choice instanceof Asn1GeneralizedTime) {
            String utcString = ((Asn1GeneralizedTime) choice).getValue().getValue();
            return TimeDecoder.decodeGeneralizedTimeUtc(utcString);
        } else {
            throw new UnsupportedOperationException(
                    "Time format not properly implemented: " + choice.getClass().getSimpleName());
        }
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler(chooser);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
