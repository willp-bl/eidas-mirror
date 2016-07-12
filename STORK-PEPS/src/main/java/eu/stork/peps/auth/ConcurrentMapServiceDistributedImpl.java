package eu.stork.peps.auth;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentMap;

/**
 * Hazelcast Distributed hashMap implementation of the cache provider.
 */
public class ConcurrentMapServiceDistributedImpl implements ConcurrentMapService {
    private static final Logger LOG = LoggerFactory.getLogger(ConcurrentMapServiceDistributedImpl.class.getName());
    private String antiReplayCacheName;
    private String hazelcastXmlConfigClassPathFileName;

    public void setAntiReplayCacheName(String antiReplayCacheName) {
        this.antiReplayCacheName = antiReplayCacheName;
    }

    public void setHazelcastXmlConfigClassPathFileName(String hazelcastXmlConfigClassPathFileName) {
        this.hazelcastXmlConfigClassPathFileName = hazelcastXmlConfigClassPathFileName;
    }

    @Override
    public ConcurrentMap<String, Boolean> getNewAntiReplayCache() {
        if (antiReplayCacheName == null) {
            throw new InvalidParameterPEPSException("Distributed Cache Configuration mismatch");
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
        mapCfg.setName(antiReplayCacheName);
        HazelcastInstance instance = Hazelcast.newHazelcastInstance(cfg);
        cfg.addMapConfig(mapCfg);
        return instance.getMap(this.antiReplayCacheName);
    }
}
