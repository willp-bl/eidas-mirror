package eu.eidas.node.auth;

import java.util.concurrent.ConcurrentMap;

/**
 *
 */
public interface ConcurrentMapService {
    /**
     * Obtains the antiReplayCache
     * @return a concurrentMap
     */
    ConcurrentMap<String, Boolean> getNewAntiReplayCache();

}
