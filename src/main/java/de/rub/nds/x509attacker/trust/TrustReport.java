/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.trust;

import java.util.List;

public class TrustReport {

    private TrustPlatform platform;

    private List<TrustPath> trustPathList;

    public TrustReport(TrustPlatform platform, List<TrustPath> trustPathList) {
        this.platform = platform;
        this.trustPathList = trustPathList;
    }

    public TrustPlatform getPlatform() {
        return platform;
    }

    public List<TrustPath> getTrustPathList() {
        return trustPathList;
    }

    public boolean hasTrustOnPlatform() {
        return !trustPathList.isEmpty();
    }
}
