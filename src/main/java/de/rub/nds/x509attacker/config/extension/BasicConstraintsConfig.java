package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.extensions.BasicConstraints;

import java.math.BigInteger;

/**
 * Configuration for the {@link BasicConstraints} extension.
 */
public class BasicConstraintsConfig extends ExtensionConfig {
    boolean caPresent = true;
    boolean ca = false;
    boolean pathLenConstraintPresent = false;
    int pathLenConstraint = 0;

    public BasicConstraintsConfig() {
        super(X509ExtensionType.BASIC_CONSTRAINTS.getOid(), "basicConstraints");
    }

    public boolean isCaPresent() {
        return caPresent;
    }

    public void setCaPresent(boolean caPresent) {
        this.caPresent = caPresent;
    }

    public boolean isCa() {
        return ca;
    }

    public void setCa(boolean ca) {
        this.ca = ca;
    }

    public boolean isPathLenConstraintPresent() {
        return pathLenConstraintPresent;
    }

    public void setPathLenConstraintPresent(boolean pathLenConstraintPresent) {
        this.pathLenConstraintPresent = pathLenConstraintPresent;
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

    // TODO: remove
    @Override
    public Asn1OctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
                                                   X509CertificateConfig previousConfig) {
        BasicConstraints basicConstraintsAsn1 = new BasicConstraints("basicConstraints");

        Asn1Boolean caAsn1 = new Asn1Boolean("ca");
        caAsn1.setValue(ca);
        basicConstraintsAsn1.setCa(caAsn1);

        if (pathLenConstraintPresent) {
            Asn1Integer pathLenConstraintAsn1 = new Asn1Integer("pathLenConstraint");
            pathLenConstraintAsn1.setValue(BigInteger.valueOf(pathLenConstraint));
            basicConstraintsAsn1.setPathLenConstraint(pathLenConstraintAsn1);
        }

        Asn1FieldSerializer serializer = new Asn1FieldSerializer(basicConstraintsAsn1);
        byte[] derEncoded = serializer.serialize();

        Asn1OctetString extensionValue = new Asn1OctetString("pathLen");
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
