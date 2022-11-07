package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.KeyType;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

public class SignatureEngineFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Maps OID's to signature engines
     */
    private final static Map<String, SignatureEngine> OID_ENGINE_MAP;
    /**
     * Maps names to signature engines
     */
    private final static Map<String, SignatureEngine> NAME_ENGINE_MAP;

    private final static List<SignatureEngine> SIGNATURE_ENGINE_LIST;

    static {
        OID_ENGINE_MAP = new HashMap<>();
        NAME_ENGINE_MAP = new HashMap<>();
        //TODO Reflection magic to find signature engines and add them to the maps
        SIGNATURE_ENGINE_LIST = new LinkedList<>();
        //TODO add to list

        Reflections reflections = new Reflections("de.rub.nds");//TODO this could be tighter to imrprove performance a little bit
        Set<Class<? extends SignatureEngine>> signatureEngineClasses = reflections.getSubTypesOf(SignatureEngine.class);
        for (Class<? extends SignatureEngine> engineClass : signatureEngineClasses) {
            if (Modifier.isAbstract(engineClass.getModifiers())) {
                LOGGER.debug("Not considering {} since it is abstract", engineClass.getSimpleName());
            } else {
                Constructor<?>[] constructors = engineClass.getConstructors();
                for (Constructor<?> constructor : constructors) {
                    if (constructor.getParameterCount() == 0) {
                        try {
                            //this is the default constructor
                            SignatureEngine engine = (SignatureEngine) constructor.newInstance();
                            if (engine.getOid() != null) {
                                OID_ENGINE_MAP.put(engine.getOid(), engine);
                            }
                            if (engine.getName() != null) {
                                OID_ENGINE_MAP.put(engine.getName(), engine);
                            }
                            SIGNATURE_ENGINE_LIST.add(engine);
                        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
                            LOGGER.error("Could not create signature engine instance");
                        }
                    }
                }
            }
        }
    }

    public static SignatureEngine getEngineForOid(final String oid) {
        return OID_ENGINE_MAP.get(oid);
    }

    public static SignatureEngine getEngineForName(final String name) {
        return NAME_ENGINE_MAP.get(name);
    }

    public static List<SignatureEngine> getEnginesForKeyType(final KeyType keyType) {
        List< SignatureEngine> listOfCompatibleEngines = new LinkedList<>();
        for (SignatureEngine engine : SIGNATURE_ENGINE_LIST) {
            if (engine.getKeyType().equals(keyType)) {
                listOfCompatibleEngines.add(engine);
            }
        }
        return listOfCompatibleEngines;
    }
}
