package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import java.io.InputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;

public class X509DhParametersParser implements X509Parser {

    public X509DhParametersParser(X509Chooser chooser, X509DhParameters x509DhParameters) {
    }

    @Override
    public void parse(InputStream inputStream) {
        throw new UnsupportedOperationException("Unimplemented method 'parse'");
    }

}
