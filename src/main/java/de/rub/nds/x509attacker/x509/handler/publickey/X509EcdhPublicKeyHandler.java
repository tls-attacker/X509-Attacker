/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey;

import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhPublicKey;

public class X509EcdhPublicKeyHandler extends X509FieldHandler<X509EcdhPublicKey> {

    public X509EcdhPublicKeyHandler(X509Chooser chooser, X509EcdhPublicKey publicKey) {
        super(chooser, publicKey);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
        context.setSubjectEcPrivateKey(config.getDefaultIssuerEcPrivateKey());
    }

    public void adjustContext() {
        EllipticCurve curve = chooser.getSubjectNamedCurve().getParameters().getGroup();
        context.setSubjectEcPublicKey(
                curve.getPoint(
                        component.getxCoordinate().getValue(),
                        component.getyCoordinate().getValue()));
    }
}
