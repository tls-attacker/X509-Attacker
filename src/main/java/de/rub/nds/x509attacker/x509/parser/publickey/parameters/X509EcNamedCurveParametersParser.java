package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import java.io.InputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.parser.X509Parser;

public class X509EcNamedCurveParametersParser implements X509Parser {

    public X509EcNamedCurveParametersParser(X509Chooser chooser,
            X509EcNamedCurveParameters x509EcNamedCurveParameters) {
    }

    @Override
    public void parse(InputStream inputStream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parse'");
    }

}
