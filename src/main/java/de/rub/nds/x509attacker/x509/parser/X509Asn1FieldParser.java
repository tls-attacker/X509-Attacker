package de.rub.nds.x509attacker.x509.parser;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1GeneralizedTime;
import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1T61String;
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.asn1.model.Asn1UnknownSet;
import de.rub.nds.asn1.model.Asn1UtcTime;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.util.Asn1Header;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;

/**
 * A parser for the X509 module that always parses the the structure of the asn1
 * field and then passes
 * the content of the field to the implementation
 */
public abstract class X509Asn1FieldParser<Field extends Asn1Field> extends Asn1Parser<Field>
        implements X509Parser {

    protected final X509Chooser chooser;

    public X509Asn1FieldParser(X509Chooser chooser, Field field) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(InputStream inputStream) {
        ParserHelper.parseStructure(encodable, inputStream);
        parseContent(new PushbackInputStream(new ByteArrayInputStream(encodable.getContent().getValue())));
    }

    protected abstract void parseContent(PushbackInputStream inputStream);
}
