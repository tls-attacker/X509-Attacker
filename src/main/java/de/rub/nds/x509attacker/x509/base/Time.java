/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.EmptyHandler;
import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.asn1.time.TimeDecoder;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.joda.time.DateTime;

/** Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Time extends Asn1Choice<X509Chooser> {

    private Time() {
        super(null);
    }

    public Time(String identifier) {
        super(
                identifier,
                new Asn1PrimitiveUtcTime<X509Chooser>("utcTime"),
                new Asn1PrimitiveGeneralizedTime<X509Chooser>("generalizedTime"));
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        return new EmptyHandler<>(chooser);
    }

    public DateTime getTimeValue() {
        Asn1Field<X509Chooser> choice = getSelectedChoice();
        if (choice == null) {
            throw new NotInitializedException(
                    "Not initialized. Prepare or parse it first to access values");
        }
        if (choice instanceof Asn1PrimitiveUtcTime<?>) {
            String utcString = ((Asn1PrimitiveUtcTime<?>) choice).getValue().getValue();
            return TimeDecoder.decodeUtc(utcString);
        } else if (choice instanceof Asn1PrimitiveGeneralizedTime<?>) {
            String utcString = ((Asn1PrimitiveGeneralizedTime<?>) choice).getValue().getValue();
            return TimeDecoder.decodeGeneralizedTimeUtc(utcString);
        } else {
            throw new UnsupportedOperationException(
                    "Time format not properly implemented: " + choice.getClass().getSimpleName());
        }
    }
}
