package eu.eidas.node.auth;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Default implementation of the cache provider - this implementation is default one, not production ready, there is no clustering and expiration implemented.
 */
public class ConcurrentMapServiceDefaultImpl implements ConcurrentMapService {
    @Override
    public ConcurrentMap<String, Boolean> getNewAntiReplayCache() {
        return new ConcurrentHashMap<String, Boolean>();
    }
}
