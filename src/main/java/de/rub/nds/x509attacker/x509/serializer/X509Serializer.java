/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.serializer;

public interface X509Serializer {
    /**
     * Serializes the X.509 object into its byte array representation.
     *
     * @return the serialized byte array representation of the X.509 object
     */
    byte[] serialize();
}
