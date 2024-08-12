package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;

/**
 * Config for unknown extensions or extensions with hardcoded content.
 */
public class UnknownConfig extends ExtensionConfig {

    private byte[] content;

    /**
     * ObjectIdentifier has to be supplied as it cannot be inferred.
     */
    public UnknownConfig(ObjectIdentifier extensionId, String name) {
        super(extensionId, name);
    }

    @Override
    public Extension getExtensionFromConfig() {
        return new Unknown("unkown");
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}
