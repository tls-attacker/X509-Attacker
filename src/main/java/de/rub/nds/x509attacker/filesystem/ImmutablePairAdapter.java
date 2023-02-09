/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import org.apache.commons.lang3.tuple.ImmutablePair;

public class ImmutablePairAdapter
        extends XmlAdapter<ImmutablePair, ImmutablePair<String, Integer>> {

    @Override
    public ImmutablePair<String, Integer> unmarshal(ImmutablePair v) throws Exception {
        return new ImmutablePair(v.getKey(), v.getValue());
    }

    @Override
    public ImmutablePair marshal(ImmutablePair<String, Integer> v) throws Exception {
        return new ImmutablePair(v.getKey(), v.getValue());
    }
}
