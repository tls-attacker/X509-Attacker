package de.rub.nds.asn1.translators.typetranslators;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1BooleanTranslator extends Asn1FieldTranslator {

    private static final Logger LOGGER = LogManager.getLogger();

    private final IntermediateAsn1Field intermediateAsn1Field;

    private final Asn1Boolean asn1Boolean;

    public Asn1BooleanTranslator(final IntermediateAsn1Field intermediateAsn1Field) {
        this(intermediateAsn1Field, new Asn1Boolean());
    }

    protected Asn1BooleanTranslator(final IntermediateAsn1Field intermediateAsn1Field, final Asn1Boolean asn1Boolean) {
        super(intermediateAsn1Field, asn1Boolean);
        this.intermediateAsn1Field = intermediateAsn1Field;
        this.asn1Boolean = asn1Boolean;
    }

    @Override
    public Asn1Boolean translate() {
        this.asn1Boolean.setBooleanValue(this.parseBooleanValue(intermediateAsn1Field.getContent()));
        return (Asn1Boolean) super.translate();
    }

    private boolean parseBooleanValue(byte[] content) {
        boolean booleanValue = false;
        if(content.length == 1) {
            if(content[0] != 0x00) {
                booleanValue = true;
            }
        }
        else {
            LOGGER.warn("Parsing Asn1Boolean with content which has an invalid content length!");
        }
        return booleanValue;
    }
}
