/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.asn1.model.Asn1GeneralizedTime;
import de.rub.nds.asn1.model.Asn1UtcTime;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.TimeContextHint;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.x509.model.Time;
import org.joda.time.DateTime;

public class TimePreparator implements X509Preparator {

    private final X509Chooser chooser;
    private final Time time;

    public TimePreparator(X509Chooser chooser, Time time) {
        this.chooser = chooser;
        this.time = time;
    }

    @Override
    public void prepare() {
        ValidityEncoding timeEncoding;
        DateTime dateTime;
        TimeField timeField;
        TimeAccurracy accurracy;
        if (time.getTimeContext() == TimeContextHint.NOT_AFTER) {
            timeEncoding = chooser.getConfig().getDefaultNotAfterEncoding();
            dateTime = chooser.getConfig().getNotAfter();
            accurracy = chooser.getConfig().getNotAfterAccurracy();
        } else if (time.getTimeContext() == TimeContextHint.NOT_BEFORE) {
            timeEncoding = chooser.getConfig().getDefaultNotBeforeEncoding();
            dateTime = chooser.getConfig().getNotBefore();
            accurracy = chooser.getConfig().getNotBeforeAccurracy();
        } else {
            throw new RuntimeException("Something went wrong. Unexpected TimeContextHint.");
        }
        switch (timeEncoding) {
            case GENERALIZED_TIME_DIFFERENTIAL:
            case GENERALIZED_TIME_LOCAL:
            case GENERALIZED_TIME_UTC:
                timeField = new Asn1GeneralizedTime("generalizedTime");
                break;
            case UTC:
            case UTC_DIFFERENTIAL:
                timeField = new Asn1UtcTime("utcTime");
                break;
            default:
                throw new UnsupportedOperationException(
                        "Unimplemented time encoding: " + timeEncoding);
        }
        time.makeSelection(timeField);
        Asn1PreparatorHelper.prepareField(timeField, dateTime, accurracy);
    }
}
