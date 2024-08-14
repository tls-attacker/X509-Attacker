/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.extensions.BasicConstraints;

/** Configuration for the {@link BasicConstraints} extension. */
public class BasicConstraintsConfig extends ExtensionConfig {
    DefaultEncodingRule includeCA = DefaultEncodingRule.FOLLOW_DEFAULT;
    boolean ca = false;
    DefaultEncodingRule includePathLenConstraint = DefaultEncodingRule.FOLLOW_DEFAULT;
    int pathLenConstraint = 0;

    public BasicConstraintsConfig() {
        super(X509ExtensionType.BASIC_CONSTRAINTS.getOid(), "basicConstraints");
    }

    public DefaultEncodingRule getIncludeCA() {
        return includeCA;
    }

    public void setIncludeCA(DefaultEncodingRule includeCA) {
        this.includeCA = includeCA;
    }

    public boolean isCa() {
        return ca;
    }

    public void setCa(boolean ca) {
        this.ca = ca;
    }

    public DefaultEncodingRule getIncludePathLenConstraint() {
        return includePathLenConstraint;
    }

    public void setIncludePathLenConstraint(DefaultEncodingRule includePathLenConstraint) {
        this.includePathLenConstraint = includePathLenConstraint;
    }

    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(int pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    @Override
    public BasicConstraints getExtensionFromConfig() {
        return new BasicConstraints("basicConstraints");
    }
}
