package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public interface X509Component {
    public X509Handler getHandler(X509Chooser chooser);

    public X509Parser getParser(X509Chooser chooser);

    public X509Serializer getSerializer(X509Chooser chooser);

    public X509Preparator getPreparator(X509Chooser chooser);
}
