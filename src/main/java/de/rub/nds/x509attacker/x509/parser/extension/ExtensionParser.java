package de.rub.nds.x509attacker.x509.parser.extension;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

/**
 * Parent parser for all extensions. Parses OID, criticality, and content bytes. Delegates content byte parsing to the
 * implementing subclass.
 */
abstract class ExtensionParser<Encodable extends Extension> extends X509ComponentContainerParser<Encodable> {

    private final Logger LOGGER = LogManager.getLogger();

    public ExtensionParser(X509Chooser chooser, Encodable extension) {
        super(chooser, extension);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        // OBJECT IDENTIFIER
        parseOid(inputStream);
        // BOOLEAN DEFAULT FALSE
        if (ParserHelper.canParse(inputStream, TagClass.UNIVERSAL, 1)) {
            parseCritical(inputStream);
        }
        // OCTET STRING
        parseExtnValue(inputStream);
        // allow extension-specific parser to take over
        parseExtensionContent(
                new BufferedInputStream(
                        new ByteArrayInputStream(
                                encodable.getExtnValue().getValue().getValue()
                        )));
        }

    private void parseOid(BufferedInputStream bufferedInputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getExtnID(), bufferedInputStream);
        LOGGER.debug("Parsed extension OID: {}", encodable.getExtnID());
    }

    private void parseCritical(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Boolean(encodable.getCritical(), inputStream);
        LOGGER.debug("Parsed critical extension: {}", encodable.getCritical());
    }

    private void parseExtnValue(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1OctetString(encodable.getExtnValue(), inputStream);
    }

    abstract void parseExtensionContent(BufferedInputStream inputStream);
}
