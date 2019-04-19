package de.rub.nds.asn1.translators.nativetranslator.fieldtranslators;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1BooleanFT extends Asn1FieldFT {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Translates an IntermediateAsn1Field into an Asn1Boolean.
     *
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @return The translated Asn1Boolean.
     */
    @Override
    public Asn1Boolean translateImmediateAsn1Field(final IntermediateAsn1Field intermediateAsn1Field) {
        Asn1Boolean asn1Boolean = new Asn1Boolean();
        this.translateAsn1Field(intermediateAsn1Field, asn1Boolean);
        this.translateAsn1Boolean(intermediateAsn1Field, asn1Boolean);
        return asn1Boolean;
    }

    protected void translateAsn1Boolean(final IntermediateAsn1Field intermediateAsn1Field, final Asn1Boolean asn1Boolean) {
        byte[] content = intermediateAsn1Field.getContent();
        boolean booleanValue = false;
        if(content.length == 0) {
            LOGGER.warn("Asn1Boolean does not contain any content. Using default value: " + booleanValue);
        }
        if(content.length > 1) {
            LOGGER.warn("Content of Asn1Boolean is not of length 1. Using first content byte only!");
        }
        if(content.length == 1) {
            booleanValue = content[0] != 0x00;
            asn1Boolean.setBooleanValue(booleanValue);
        }
    }
}
