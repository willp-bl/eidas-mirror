package eu.stork.peps.auth.engine.core;

import eu.stork.peps.auth.engine.STORKSAMLEngine;

import java.util.Properties;

/**
 * provides StorkSAMLEngine instances
 */
public interface StorkSAMLEngineFactoryI {
    /**
     *
     * @param name the name of the engine
     * @param props additional properties used for initializing the engine
     * @return
     */
    STORKSAMLEngine getEngine(String name, Properties props);

    /**
     * releases the provided engine
     * @param engine
     */
    void releaseEngine(STORKSAMLEngine engine);

    /**
     *
     * @param name
     * @return the number of active engines with the given name (or total count if name is null)
     */
    int getActiveEngineCount(String name);
}
