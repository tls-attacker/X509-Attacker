package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class DistributionPointName extends Asn1Choice implements X509Component {

    public DistributionPointName(String identifier) {
        super(identifier, new GeneralNames("generalNames", 0), new RelativeDistinguishedName("rdnSequence", 1));
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
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPreparator'");
    }

}
