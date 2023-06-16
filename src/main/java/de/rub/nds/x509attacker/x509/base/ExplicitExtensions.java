package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class ExplicitExtensions extends Asn1Explicit<Extensions> implements X509Component {

    public ExplicitExtensions(String identifier, Integer expectedTagNumber) {
        super(identifier, expectedTagNumber, new Extensions(identifier));
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getHandler'");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getParser'");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getSerializer'");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getPreparator'");
    }

}
