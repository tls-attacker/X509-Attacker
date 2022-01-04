/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.signatureengine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author josh
 */
public class BouncyCastleProviderSingleton {

    private static BouncyCastleProvider instance;

    private BouncyCastleProviderSingleton() {
    }

    // static block initialization for exception handling
    static {
        try {
            instance = new BouncyCastleProvider();
        } catch (Exception e) {
            throw new RuntimeException("Exception occured in creating singleton instance");
        }
    }

    public static BouncyCastleProvider getInstance() {
        return instance;
    }
}
