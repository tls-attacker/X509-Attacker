package de.rub.nds.x509attacker.x509.parser.extension;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.BasicConstraints;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedInputStream;

public class BasicConstraintsParser extends ExtensionParser<BasicConstraints> {

    private static final Logger LOGGER = LogManager.getLogger();

    public BasicConstraintsParser(X509Chooser chooser, BasicConstraints basicConstraints) {
        super(chooser, basicConstraints);
    }

    @Override
    protected void parseExtensionContent(BufferedInputStream inputStream) {
        if (hasCAField(inputStream)) {
            parseCA(inputStream);
        }
        if (hasPathLenConstraint(inputStream)) {
            parsePathLengthConstraint(inputStream);
            if (!encodable.getCa().getValue().getValue()) {
                LOGGER.debug("PathLenConstraint set on non-CA certificate!");
            }
        }
    }

    private void parseCA(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Boolean(encodable.getCa(), inputStream);
        LOGGER.debug("Parsed Basic Constraint CA: {}", encodable.getCa());
    }

    private void parsePathLengthConstraint(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getPathLenConstraint(), inputStream);
        LOGGER.debug("Parsed Basic Constraint Path Length: {}", encodable.getPathLenConstraint());
    }

    private boolean hasCAField(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.UNIVERSAL, 1);
    }

    private boolean hasPathLenConstraint(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.UNIVERSAL, 2);
    }
}
