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
