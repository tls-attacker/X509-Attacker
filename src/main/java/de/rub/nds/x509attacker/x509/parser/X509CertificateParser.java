package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.io.IOException;
import java.io.InputStream;

public class X509CertificateParser extends X509ComponentParser<X509Certificate> {

    public X509CertificateParser(X509Certificate field) {
        super(field);
    }

    @Override
    protected void parseIndividualContentFields(InputStream inputStream) throws IOException {
        for(Asn1Encodable field : encodable.getChildren())
        {
            field.getParser()
        }
    }


}
