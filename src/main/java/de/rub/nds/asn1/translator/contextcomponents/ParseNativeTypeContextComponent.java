/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.asn1.translator.contextcomponents;

import de.rub.nds.asn1.translator.ContextComponent;
import de.rub.nds.asn1.translator.ContextComponentOption;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ParseNativeTypeContextComponent extends ContextComponent {

    private static ContextComponentOption<?>[] contextComponentOptions = new ContextComponentOption<?>[] {
        new Asn1BooleanCCO(), new Asn1ConstructedBitStringCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedGeneralizedTimeCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedIa5StringCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedOctetStringCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedPrintableStringCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedT61StringCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedUtcTimeCCO(ParseNativeTypesContext.NAME),
        new Asn1ConstructedUtf8StringCCO(ParseNativeTypesContext.NAME),
        new Asn1EncapsulatingBitStringCCO(ParseNativeTypesContext.NAME),
        new Asn1EncapsulatingOctetStringCCO(ParseNativeTypesContext.NAME), new Asn1EndOfContentCCO(),
        new Asn1IntegerCCO(), new Asn1NullCCO(), new Asn1ObjectIdentifierCCO(), new Asn1PrimitiveBitStringCCO(),
        new Asn1PrimitiveGeneralizedTimeCCO(), new Asn1PrimitiveIa5StringCCO(), new Asn1PrimitiveOctetStringCCO(),
        new Asn1PrimitivePrintableStringCCO(), new Asn1PrimitiveT61StringCCO(), new Asn1PrimitiveUtcTimeCCO(),
        new Asn1PrimitiveUtf8StringCCO(), new Asn1SequenceCCO(ParseNativeTypesContext.NAME),
        new Asn1SetCCO(ParseNativeTypesContext.NAME) };

    public ParseNativeTypeContextComponent() {
        super("", "", contextComponentOptions, false, true);
    }
}
