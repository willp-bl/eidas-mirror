package eu.eidas.auth.commons.cache;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentMap;

/**
 * Hazelcast Distributed hashMap implementation of the cache provider.
 */
public class ConcurrentMapServiceDistributedImpl implements ConcurrentMapService {
    private static final Logger LOG = LoggerFactory.getLogger(ConcurrentMapServiceDistributedImpl.class.getName());
    private String cacheName;
    private String hazelcastXmlConfigClassPathFileName;

    public void setCacheName(String cacheName) {
        this.cacheName = cacheName;
    }

    public void setHazelcastXmlConfigClassPathFileName(String hazelcastXmlConfigClassPathFileName) {
        this.hazelcastXmlConfigClassPathFileName = hazelcastXmlConfigClassPathFileName;
    }

    @Override
    public ConcurrentMap getNewMapCache() {
        if (cacheName == null) {
            throw new InvalidParameterEIDASException("Distributed Cache Configuration mismatch");
        }
        Config cfg;
        if (hazelcastXmlConfigClassPathFileName != null) {
            LOG.trace("loading hazelcast config from " + hazelcastXmlConfigClassPathFileName);
            cfg = new ClasspathXmlConfig(hazelcastXmlConfigClassPathFileName);
        } else {
            LOG.trace("loading hazelcast config from <DEFAULT>");
            cfg = new Config();
        }
        MapConfig mapCfg = new MapConfig();
        mapCfg.setName(cacheName);
        HazelcastInstance instance = Hazelcast.newHazelcastInstance(cfg);
        cfg.addMapConfig(mapCfg);
        return instance.getMap(this.cacheName);
    }
}
