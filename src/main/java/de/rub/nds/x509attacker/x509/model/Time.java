/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1GeneralizedTime;
import de.rub.nds.asn1.model.Asn1UtcTime;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.TimeContextHint;
import de.rub.nds.x509attacker.x509.handler.TimeHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509ChoiceParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.TimePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509ChoiceSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import org.joda.time.DateTime;

public class Time extends Asn1Choice implements X509Component, TimeField {

    private final TimeContextHint timeContext;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private Time() {
        super("time", new Asn1GeneralizedTime("generalizedTime"), new Asn1UtcTime("utcTime"));
        timeContext = null;
    }

    public Time(String identifier, TimeContextHint timeContext) {
        super(identifier, new Asn1GeneralizedTime("generalizedTime"), new Asn1UtcTime("utcTime"));
        this.timeContext = timeContext;
    }

    public TimeContextHint getTimeContext() {
        return timeContext;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new TimeHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509ChoiceParser(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509ChoiceSerializer<Time>(this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new TimePreparator(chooser, this);
    }

    @Override
    public DateTime getTimeValue() {
        return ((TimeField) getSelectedChoice()).getTimeValue();
    }

    @Override
    public void setValue(String timeValue) {
        ((TimeField) getSelectedChoice()).setValue(timeValue);
    }
}
