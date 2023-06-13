package de.rub.nds.x509attacker.x509.parser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.TagConstructed;
import de.rub.nds.asn1.constants.TagNumber;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.util.Asn1Header;
import de.rub.nds.x509attacker.chooser.X509Chooser;

/**
 * A parser for the X509 module that always parses the the structure of the asn1
 * field and then passes
 * the content of the field to the implementation
 */
public abstract class X509Asn1FieldParser<Field extends Asn1Field> extends Asn1FieldParser<Field>
        implements X509Parser {

    protected final X509Chooser chooser;

    public X509Asn1FieldParser(X509Chooser chooser, Field field) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(InputStream inputStream) {
        parseStructure(encodable, inputStream);
        parseContent(new PushbackInputStream(new ByteArrayInputStream(encodable.getContent().getValue())));
    }

    protected abstract void parseContent(PushbackInputStream inputStream);

    public boolean canParse(PushbackInputStream inputStream, TagClass tagClass, TagNumber... tagNumbers) {
        Asn1Header header = lookAhead(inputStream);
        if (header.getTagClass() != tagClass) {
            return false;
        }
        for (TagNumber tagNumber : tagNumbers) {
            if (header.getTagNumber() == tagNumber.getIntValue()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Look ahead to the next field in the stream.
     *
     * @param inputStream
     *                    The stream to look ahead in.
     * @return The header of the next field.
     */
    protected Asn1Header lookAhead(PushbackInputStream inputStream) {
        try {
            inputStream.mark(inputStream.available());
            byte[] tagOctets = this.parseTagOctets(inputStream);
            int tagClass = this.parseTagClass(tagOctets[0]);
            boolean constructed = this.parseTagConstructed(tagOctets[0]);
            int parseTagNumber = this.parseTagNumber(tagOctets);
            byte[] lengthOctets;
            lengthOctets = this.parseLengthOctets(inputStream);

            BigInteger parseLength = this.parseLength(lengthOctets);
            inputStream.reset();
            return new Asn1Header(TagClass.fromIntValue(tagClass), parseTagNumber, parseLength,
                    TagConstructed.fromBooleanValue(constructed));
        } catch (IOException e) {
            throw new ParserException("Failed to look ahead.", e);
        }
    }
}
