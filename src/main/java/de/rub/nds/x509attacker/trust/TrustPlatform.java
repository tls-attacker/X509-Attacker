/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.trust;

import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class TrustPlatform {

    private final String platform;

    private final String version;

    private final String url;

    private final Date lastUpdate;

    private final List<X509Certificate> trustAnchors;

    private final List<X509Certificate> blockedTrustAnchors;

    public TrustPlatform() {
        blockedTrustAnchors = null;
        trustAnchors = null;
        lastUpdate = null;
        platform = null;
        url = null;
        version = null;
    }

    public TrustPlatform(
            String platform,
            String version,
            String url,
            Date lastUpdate,
            List<X509Certificate> certificateEntries,
            List<X509Certificate> blockedCertificateEntries) {
        this.platform = platform;
        this.version = version;
        this.url = url;
        this.lastUpdate = lastUpdate;
        this.trustAnchors = certificateEntries;
        this.blockedTrustAnchors = blockedCertificateEntries;
    }

    public String getPlatform() {
        return platform;
    }

    public String getVersion() {
        return version;
    }

    public String getUrl() {
        return url;
    }

    public Date getLastUpdate() {
        return lastUpdate;
    }

    public List<X509Certificate> getTrustAnchors() {
        return trustAnchors;
    }

    public List<X509Certificate> getBlockedTrustAnchors() {
        return blockedTrustAnchors;
    }

    public boolean isTrusted(byte[] sha256Fingerprint) {
        for (X509Certificate anchor : trustAnchors) {
            if (Arrays.equals(anchor.getSha256Fingerprint(), sha256Fingerprint)) {
                return true;
            }
        }
        return false;
    }

    public boolean isBlacklisted(byte[] sha256Fingerprint) {
        for (X509Certificate anchor : blockedTrustAnchors) {
            if (Arrays.equals(anchor.getSha256Fingerprint(), sha256Fingerprint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the trust anchor with a given sha256 fingerprint.If the subject is not trusted or not
     * found null is returned
     *
     * @param sha256Fingerprint The sha2-256 fingerprint of the certificate that we are searching
     *     for
     * @return The relevant trustAnchor or null if not found
     */
    public X509Certificate getTrustedCertificateEntry(byte[] sha256Fingerprint) {
        for (X509Certificate anchor : trustAnchors) {
            if (Arrays.equals(anchor.getSha256Fingerprint(), sha256Fingerprint)) {
                return anchor;
            }
        }
        return null;
    }

    /**
     * Returns the blacklisted anchor with a given sha256 fingerprint.If the subject is not
     * blacklisted or not found null is returned
     *
     * @param sha256Fingerprint The sha2-256 fingerprint of the certificate that we are searching
     *     for
     * @return The relevant trustAnchor or null if not found
     */
    public X509Certificate getBlacklistedCertificateEntry(byte[] sha256Fingerprint) {
        for (X509Certificate anchor : blockedTrustAnchors) {
            if (Arrays.equals(anchor.getSha256Fingerprint(), sha256Fingerprint)) {
                return anchor;
            }
        }
        return null;
    }
}
