package eu.eidas.auth.engine.core;

import eu.eidas.auth.engine.EIDASSAMLEngine;

import java.util.Properties;

/**
 * provides SAMLEngine instances
 */
public interface EidasSAMLEngineFactoryI {
    /**
     *
     * @param name the name of the engine
     * @param props additional properties used for initializing the engine
     * @return
     */
    EIDASSAMLEngine getEngine(String name, Properties props);

    /**
     * releases the provided engine
     * @param engine
     */
    void releaseEngine(EIDASSAMLEngine engine);

    /**
     *
     * @param name
     * @return the number of active engines with the given name (or total count if name is null)
     */
    int getActiveEngineCount(String name);
}
