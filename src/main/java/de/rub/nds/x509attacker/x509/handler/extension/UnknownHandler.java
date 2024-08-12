package de.rub.nds.x509attacker.x509.handler.extension;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;

public class UnknownHandler extends X509FieldHandler<Unknown> {

    public UnknownHandler(X509Chooser chooser, Unknown component) {
        super(chooser, component);
    }

    @Override
    public void adjustContextAfterParse() {
        // Nothing to do right now
    }

    @Override
    public void adjustContextAfterPrepare() {
        // Nothing to do right now
    }
}
