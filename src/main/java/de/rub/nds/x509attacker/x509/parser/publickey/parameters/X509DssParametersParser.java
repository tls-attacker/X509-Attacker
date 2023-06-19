package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import java.io.InputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.parser.X509Parser;

public class X509DssParametersParser implements X509Parser {

    public X509DssParametersParser(X509Chooser chooser, X509DssParameters x509DssParameters) {
    }

    @Override
    public void parse(InputStream inputStream) {
        throw new UnsupportedOperationException("Unimplemented method 'parse'");
    }

}
