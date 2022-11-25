/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

public class SignatureEngineFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Maps SignatureAlgorithms to signature Engines */
    private static final Map<X509SignatureAlgorithm, SignatureEngine> signatureEngineMap;

    static {
        signatureEngineMap = new HashMap<>();

        Reflections reflections =
                new Reflections(
                        "de.rub.nds"); // TODO this could be tighter to imrprove performance a
        // little bit
        Set<Class<? extends SignatureEngine>> signatureEngineClasses =
                reflections.getSubTypesOf(SignatureEngine.class);
        for (Class<? extends SignatureEngine> engineClass : signatureEngineClasses) {
            if (Modifier.isAbstract(engineClass.getModifiers())) {
                LOGGER.debug(
                        "Not considering {} since it is abstract", engineClass.getSimpleName());
            } else {
                Constructor<?>[] constructors = engineClass.getConstructors();
                for (Constructor<?> constructor : constructors) {
                    if (constructor.getParameterCount() == 0) {
                        try {
                            // this is the default constructor
                            SignatureEngine engine = (SignatureEngine) constructor.newInstance();
                            signatureEngineMap.put(engine.getSignatureAlgorithm(), engine);
                        } catch (InstantiationException
                                | IllegalAccessException
                                | IllegalArgumentException
                                | InvocationTargetException ex) {
                            LOGGER.error("Could not create signature engine instance");
                        }
                    }
                }
            }
        }
    }

    public static SignatureEngine getEngineForOid(final String oidString) {
        ObjectIdentifier oid = new ObjectIdentifier(oidString);
        X509SignatureAlgorithm signatureAlgorithm =
                X509SignatureAlgorithm.decodeFromOidBytes(oid.getEncoded());
        return signatureEngineMap.get(signatureAlgorithm);
    }

    public static SignatureEngine getEngine(X509SignatureAlgorithm signatureAlgorithm) {
        return signatureEngineMap.get(signatureAlgorithm);
    }
}
