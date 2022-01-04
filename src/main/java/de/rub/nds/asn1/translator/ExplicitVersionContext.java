/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExplicitVersionContext extends Context {

    public static String NAME = "ExplicitVersionContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] { new ContextComponent("version",
        "Version", new ContextComponentOption<?>[] { new Asn1IntegerCCO() }, false, false), };

    public ExplicitVersionContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
