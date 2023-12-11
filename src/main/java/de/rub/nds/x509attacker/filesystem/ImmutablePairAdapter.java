/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import org.apache.commons.lang3.tuple.ImmutablePair;

public class ImmutablePairAdapter
        extends XmlAdapter<ImmutablePair<String, Integer>, ImmutablePair<String, Integer>> {

    @Override
    public ImmutablePair<String, Integer> unmarshal(ImmutablePair<String, Integer> v)
            throws Exception {
        return new ImmutablePair<>(v.getKey(), v.getValue());
    }

    @Override
    public ImmutablePair<String, Integer> marshal(ImmutablePair<String, Integer> v)
            throws Exception {
        return new ImmutablePair<>(v.getKey(), v.getValue());
    }
}
