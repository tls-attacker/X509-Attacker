package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1ChoiceEncoder extends Asn1Encoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Choice asn1Choice;

    public Asn1ChoiceEncoder(Asn1Choice asn1Choice) {
        this.asn1Choice = asn1Choice;
    }

    @Override
    public byte[] encode() {
        byte[] result = new byte[0];
        Asn1Encodable asn1Encodable = this.asn1Choice.getChosenAsn1Encodable();
        if(asn1Encodable != null) {
            result = asn1Encodable.getEncoder().encode();
        }
        else {
            LOGGER.warn("Instance of choice type " + this.asn1Choice.getClass() + " does not contain a chosen element!");
        }
        return result;
    }

    @Override
    public Asn1Field encodeAndGetAsn1Field() {
        Asn1Encodable asn1Encodable = this.asn1Choice.getChosenAsn1Encodable();
        Asn1Field result = null;
        if(asn1Encodable != null) {
            result = asn1Encodable.getEncoder().encodeAndGetAsn1Field();
        }
        return result;
    }
}
