package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public interface X509Component {
    public X509Handler getHandler(X509Chooser chooser);

    public X509Parser getParser(X509Chooser chooser);

    public X509Serializer getSerializer(X509Chooser chooser);

    public X509Preparator getPreparator(X509Chooser chooser);
}
