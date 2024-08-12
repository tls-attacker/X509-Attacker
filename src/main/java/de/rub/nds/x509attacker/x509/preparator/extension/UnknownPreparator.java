package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.UnknownConfig;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;

/**
 * Preparator for {@link Unknown} extension. Simply sets the configured static bytes.
 */
public class UnknownPreparator extends ExtensionPreparator<Unknown, UnknownConfig> {


    public UnknownPreparator(X509Chooser chooser, Unknown container, UnknownConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        field.setContent(config.getContent());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return field.getContent().getValue();
    }
}
