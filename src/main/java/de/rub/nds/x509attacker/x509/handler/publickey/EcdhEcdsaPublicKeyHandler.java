/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey;

import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class EcdhEcdsaPublicKeyHandler extends X509Handler {

    private final EcdhEcdsaPublicKey publicKey;

    public EcdhEcdsaPublicKeyHandler(X509Chooser chooser, EcdhEcdsaPublicKey publicKey) {
        super(chooser);
        this.publicKey = publicKey;
    }

    @Override
    public void adjustContext() {
        X509NamedCurve subjectNamedCurve = chooser.getSubjectNamedCurve();
        EllipticCurve curve = subjectNamedCurve.getParameters().getCurve();
        chooser.getContext()
                .setSubjectEcPublicKey(
                        curve.getPoint(
                                publicKey.getxCoordinate().getValue(),
                                publicKey.getyCoordinate().getValue()));
    }
}
