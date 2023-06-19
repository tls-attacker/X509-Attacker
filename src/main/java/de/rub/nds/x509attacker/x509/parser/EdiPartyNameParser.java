package de.rub.nds.x509attacker.x509.model;

import java.io.InputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;

public class EdiPartyNameParser implements X509Parser {

    public EdiPartyNameParser(X509Chooser chooser, EdiPartyName ediPartyName) {
    }

    @Override
    public void parse(InputStream inputStream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parse'");
    }

}
