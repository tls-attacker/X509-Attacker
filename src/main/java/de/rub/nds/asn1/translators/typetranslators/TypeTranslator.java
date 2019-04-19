package de.rub.nds.asn1.translators.typetranslators;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.translators.TranslatorException;

public interface TypeTranslator {
    Asn1Encodable translate() throws TranslatorException;
}
