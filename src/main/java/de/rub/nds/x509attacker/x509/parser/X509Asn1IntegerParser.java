package de.rub.nds.x509attacker.x509.parser;

import java.io.InputStream;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;

public class X509Asn1IntegerParser extends Asn1FieldParser<Asn1Integer>
        implements X509Parser {

    protected final X509Chooser chooser;

    public X509Asn1IntegerParser(Asn1Integer field, X509Chooser chooser) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(InputStream inputStream) {
        parseAsn1Integer(encodable, inputStream);
    }
}
