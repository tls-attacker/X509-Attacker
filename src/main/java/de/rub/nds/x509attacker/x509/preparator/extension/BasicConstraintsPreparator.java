package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.x509.model.extensions.BasicConstraints;

public class BasicConstraintsPreparator extends ExtensionPreparator<BasicConstraints, BasicConstraintsConfig> {

    public BasicConstraintsPreparator(X509Chooser chooser, BasicConstraints container, BasicConstraintsConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        // TODO: continue here
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        // TODO: return new byte[0];
    }
}
