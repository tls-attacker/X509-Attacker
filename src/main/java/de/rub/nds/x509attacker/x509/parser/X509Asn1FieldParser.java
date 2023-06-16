package de.rub.nds.x509attacker.x509.parser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.TagConstructed;
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
import de.rub.nds.asn1.model.Asn1UnknownField;
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.asn1.model.Asn1UnknownSet;
import de.rub.nds.asn1.model.Asn1UtcTime;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.asn1.util.Asn1Header;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;

/**
 * A parser for the X509 module that always parses the the structure of the asn1
 * field and then passes
 * the content of the field to the implementation
 */
public abstract class X509Asn1FieldParser<Field extends Asn1Field> extends Asn1FieldParser<Field>
        implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

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

    /**
     * Parses the next field in the stream as the provided tag number. Parses as
     * unknown if the
     * tag number in the stream mismatches or if the tag number is not implemented.
     * The tagClass has to be universal, otherwise a parser exception is thrown. The
     * parameter is there for a sanity check.
     *
     * @param inputStream the stream to parse from
     * @param tagClass    the tag class to parse
     * @param tagNumber   the tag number to parse
     * @return the parsed field
     */
    protected Asn1Field parseTagNumberOrUnkownField(PushbackInputStream inputStream, TagClass tagClass,
            UniversalTagNumber... tagNumbers) {
        if (tagNumbers.length == 0) {
            throw new ParserException("No tag numbers provided");
        }
        if (tagClass != TagClass.UNIVERSAL) {
            throw new ParserException("Cannot parse this tag number generically.");
        }
        Asn1Header header = lookAhead(inputStream);
        UniversalTagNumber foundNumber = null;
        if (header.getTagClass() == tagClass) {
            for (UniversalTagNumber tagNumber : tagNumbers) {
                if (tagNumber != null && header.getTagNumber() == tagNumber.getIntValue()) {
                    foundNumber = tagNumber;
                }
            }
        }
        if (foundNumber == null) {
            return parseUnknown(inputStream);
        } else {
            return parseTagNumberField(inputStream, foundNumber);
        }
    }

    /**
     * Strictly parses the next field in the stream as of of the provided tag
     * number.
     * Throws a ParserException if the next tag number is not exepected. If
     * a not implemented tag number is requested an unknown field is parsed.
     * 
     * @param inputStream the stream to parse from
     * @param tagClass    the tag class to parse
     * @param tagNumbers  The tag numbers to parse
     * @return
     */
    protected Asn1Field parseTagNumberField(PushbackInputStream inputStream, TagClass tagClass,
            UniversalTagNumber... tagNumbers) {
        if (tagClass != TagClass.UNIVERSAL) {
            throw new ParserException("Cannot parse this tag number generically.");
        }
        Asn1Header header = lookAhead(inputStream);
        UniversalTagNumber foundNumber = null;
        if (header.getTagClass() == tagClass) {
            for (UniversalTagNumber tagNumber : tagNumbers) {
                if (header.getTagNumber() == tagNumber.getIntValue()) {
                    foundNumber = tagNumber;
                }
            }
        }
        if (foundNumber == null) {
            throw new ParserException("Unexpected tagNumber. Found: " + header.getTagNumber() + " but expected "
                    + Arrays.toString(tagNumbers));
        } else {
            return parseTagNumberField(inputStream, foundNumber);
        }
    }

    private Asn1Field parseTagNumberField(PushbackInputStream inputStream, UniversalTagNumber tagNumber) {
        switch (tagNumber) {
            case BIT_STRING:
                Asn1BitString bitstring = new Asn1BitString("bitString");
                parseAsn1BitString(bitstring, inputStream);
                return bitstring;
            case BOOLEAN:
                Asn1Boolean asn1Boolean = new Asn1Boolean("boolean");
                parseAsn1Boolean(asn1Boolean, inputStream);
                return asn1Boolean;
            case GENERALIZEDTIME:
                Asn1GeneralizedTime asn1GeneralizedTime = new Asn1GeneralizedTime("generalizedTime");
                parseAsn1GeneralizedTime(asn1GeneralizedTime, inputStream);
                return asn1GeneralizedTime;
            case IA5STRING:
                Asn1Ia5String asn1Ia5String = new Asn1Ia5String("ia5String");
                parseAsn1Ia5String(asn1Ia5String, inputStream);
                return asn1Ia5String;
            case INTEGER:
                Asn1Integer asn1Integer = new Asn1Integer("integer");
                parseAsn1Integer(asn1Integer, inputStream);
                return asn1Integer;
            case NULL:
                Asn1Null asn1Null = new Asn1Null("null");
                parseAsn1Null(asn1Null, inputStream);
                return asn1Null;
            case OCTET_STRING:
                Asn1OctetString asn1OctetString = new Asn1OctetString("octetString");
                parseAsn1OctetString(asn1OctetString, inputStream);
                return asn1OctetString;
            case PRINTABLESTRING:
                Asn1PrintableString asn1PrintableString = new Asn1PrintableString("printableString");
                parseAsn1PrintableString(asn1PrintableString, inputStream);
                return asn1PrintableString;
            case OBJECT_IDENTIFIER:
                Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier("objectIdentifier");
                parseAsn1ObjectIdentifier(asn1ObjectIdentifier, inputStream);
                return asn1ObjectIdentifier;
            case SEQUENCE:
                Asn1UnknownSequence asn1UnknownSequence = new Asn1UnknownSequence("sequence");
                parseStructure(asn1UnknownSequence, inputStream);
                return asn1UnknownSequence;
            case SET:
                Asn1UnknownSet asn1UnknownSet = new Asn1UnknownSet("set");
                parseStructure(asn1UnknownSet, inputStream);
                return asn1UnknownSet;
            case T61STRING:
                Asn1T61String asn1t61String = new Asn1T61String("t61String");
                parseAsn1T61String(asn1t61String, inputStream);
                return asn1t61String;
            case UTCTIME:
                Asn1UtcTime asn1UtcTime = new Asn1UtcTime("utcTime");
                parseAsn1UtcTime(asn1UtcTime, inputStream);
                return asn1UtcTime;
            case UTF8STRING:
                Asn1Utf8String asn1Utf8String = new Asn1Utf8String("utf8String");
                parseAsn1Utf8String(asn1Utf8String, inputStream);
                return asn1Utf8String;
            default:
                LOGGER.warn(
                        "Could theoretically parse tag number {} but this is not implemented yet. Parsing as unknown.",
                        tagNumber);
                return parseUnknown(inputStream);
        }
    }

    private Asn1Field parseUnknown(PushbackInputStream inputStream) {
        Asn1UnknownField unknownField = new Asn1UnknownField("unknown");
        parseStructure(unknownField, inputStream);
        return unknownField;
    }

    protected UniversalTagNumber canParse(PushbackInputStream inputStream, TagClass tagClass, UniversalTagNumber... tagNumbers) {
        Asn1Header header = lookAhead(inputStream);
        if (header.getTagClass() != tagClass) {
            return null;
        }
        for (UniversalTagNumber tagNumber : tagNumbers) {
            if (header.getTagNumber() == tagNumber.getIntValue()) {
                return tagNumber;
            }
        }
        return null;
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
