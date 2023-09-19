/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.protocol.exception.ContextHandlingException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.Time;

public class TimeHandler implements X509Handler {

    private X509Context context;

    private Time time;

    public TimeHandler(X509Chooser chooser, Time time) {
        this.context = chooser.getContext();
        this.time = time;
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
    }

    public void adjustContext() {
        switch (time.getTimeContext()) {
            case NOT_AFTER:
                context.setNotAfter(time.getTimeValue());
                break;
            case NOT_BEFORE:
                context.setNotBefore(time.getTimeValue());
                break;
            default:
                throw new ContextHandlingException(
                        "Cannot adjust context. Unexpected TimeContextHint: "
                                + time.getTimeContext());
        }
    }
}
