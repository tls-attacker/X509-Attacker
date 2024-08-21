/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.util.ArrayList;
import java.util.List;

/**
 * Parent preparator for {@link Extension} objects. Prepares the OID, criticality, and extension
 * bytes. Delegates extension preparation to the implementing subclass.
 */
public abstract class ExtensionPreparator<
                Encodable extends Extension<Config>, Config extends ExtensionConfig>
        extends X509ContainerPreparator<Encodable> {

    protected final Config config;

    public ExtensionPreparator(X509Chooser chooser, Encodable container, Config config) {
        super(chooser, container);
        this.config = config;
    }

    @Override
    public void prepareSubComponents() {
        Asn1PreparatorHelper.prepareField(field.getExtnID(), config.getExtensionId());
        Asn1PreparatorHelper.prepareField(field.getCritical(), config.isCritical());
        extensionPrepareSubComponents();
        Asn1PreparatorHelper.prepareField(field.getExtnValue(), extensionEncodeChildrenContent());
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        // always include oid
        children.add(field.getExtnID());

        // omit critical if false default
        if (config.getIncludeCritical() == DefaultEncodingRule.ENCODE
                || (config.getIncludeCritical() == DefaultEncodingRule.FOLLOW_DEFAULT
                        && config.isCritical())) {
            children.add(field.getCritical());
        }
        children.add(field.getExtnValue());
        return encodeChildren(children);
    }

    public abstract void extensionPrepareSubComponents();

    public abstract byte[] extensionEncodeChildrenContent();
}
