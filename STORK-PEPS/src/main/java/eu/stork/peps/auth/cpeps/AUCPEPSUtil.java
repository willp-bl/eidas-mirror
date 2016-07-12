package eu.stork.peps.auth.cpeps;

import eu.stork.peps.auth.AUPEPSUtil;
import eu.stork.peps.auth.ConcurrentMapService;
import eu.stork.peps.auth.commons.STORKAuthnResponse;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class AUCPEPSUtil extends AUPEPSUtil {
    /**
     * Logger object.
     */
    protected static final Logger LOGGER = LoggerFactory.getLogger(AUCPEPSUtil.class.getName());
    /**
     * Configuration file.
     */
    private Properties configs;

    public AUCPEPSUtil() {
        // default constructor for use without concurrentMapService
    }

    public AUCPEPSUtil(final ConcurrentMapService concurrentMapService) {
        // Obtaining the anti-replay cache service provider defined in configuration and call it for setting up cache
        setAntiReplayCache(concurrentMapService.getNewAntiReplayCache());
    }

    /**
     * Setter for configs.
     * @param confs The configs to set.
     * @see Properties
     */
    public void setConfigs(final Properties confs) {
        this.configs = confs;
    }

    /**
     * Getter for configs.
     * @return configs The configs value.
     * @see Properties
     */
    public Properties getConfigs() {
        return configs;
    }

    /**
     * Obtains the key property value from property file
     * @param key the key
     * @return the value
     * TODO : refactor this
     */
    public String getProperty(String key){
        if (StringUtils.isEmpty(key) || configs==null) {
            LOGGER.error("BUSINESS EXCEPTION : Config file is null {} or key to retrieve is null {}", configs, key);
            return null;
        }
        return configs.getProperty(key);
    }
    public void setMetadatUrlToAuthnResponse(final String metadataUrl, STORKAuthnResponse authnResponse){
        if(metadataUrl!=null && !metadataUrl.isEmpty()) {
            authnResponse.setIssuer(metadataUrl);
        }
    }
}
