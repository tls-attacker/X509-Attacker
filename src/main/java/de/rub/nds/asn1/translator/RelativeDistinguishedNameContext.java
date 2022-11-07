/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class RelativeDistinguishedNameContext extends Context {

    public static final String NAME = "RelativeDistinguishedNameContext";

    private static final ContextComponent[] contextComponents
            = new ContextComponent[]{new ContextComponent("attributeTypeAndValue", "AttributeTypeAndValue",
                        new ContextComponentOption<?>[]{new Asn1SequenceCCO(AttributeTypeAndValueContext.NAME)}, false, true)};

    public RelativeDistinguishedNameContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
