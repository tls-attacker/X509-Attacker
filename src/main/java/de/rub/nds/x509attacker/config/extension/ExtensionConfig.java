package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.x509.model.Extension;

/**
 * Abstract parent class of all Extension Configurations. Holds whether the extensions will be prepared, its criticality, and OID.
 */
public abstract class ExtensionConfig {
    private final ObjectIdentifier extensionId;
    private final String name;
    private boolean present = false;
    private boolean critical = false;

    private DefaultEncodingRule includeCritical = DefaultEncodingRule.FOLLOW_DEFAULT;

    public ExtensionConfig(ObjectIdentifier extensionId, String name) {
        this.extensionId = extensionId;
        this.name = name;
    }

    public ObjectIdentifier getExtensionId() {
        return extensionId;
    }

    public boolean isPresent() {
        return present;
    }

    public void setPresent(boolean present) {
        this.present = present;
    }

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    public DefaultEncodingRule getIncludeCritical() {
        return includeCritical;
    }

    public void DefaultEncodingRule(DefaultEncodingRule includeCritical) {
        this.includeCritical = includeCritical;
    }

    public abstract Extension getExtensionFromConfig();

    // TODO: needed?
    public Extension getExtensionFromConfigOld(X509CertificateConfig certificateConfig,
                                            X509CertificateConfig previousConfig) {
        Extension extensionAsn1 = new Extension(name);

        Asn1ObjectIdentifier extnIdAsn1 = new Asn1ObjectIdentifier("extnId");
        extnIdAsn1.setValue(extensionId);
        extensionAsn1.setExtnID(extnIdAsn1);

        if (critical) {
            Asn1Boolean criticalAsn1 = new Asn1Boolean("critical");
            criticalAsn1.setValue(critical);
            extensionAsn1.setCritical(criticalAsn1);
        }

        Asn1OctetString extnValueAsn1 = getContentAsn1Structure(certificateConfig, previousConfig);
        extnValueAsn1.setIdentifier("extnValue");
        extensionAsn1.setExtnValue(extnValueAsn1);

        return extensionAsn1;
    }
}
