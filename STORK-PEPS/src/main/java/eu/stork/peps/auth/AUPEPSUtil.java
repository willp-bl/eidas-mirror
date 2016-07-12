package eu.stork.peps.auth;

import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.engine.core.SAMLExtensionFormat;
import eu.stork.peps.exceptions.STORKSAMLEngineRuntimeException;
import eu.stork.peps.logging.LoggingMarkerMDC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.concurrent.ConcurrentMap;

/**
 * Abstract part used for the anti replay cache.
 */
public abstract class AUPEPSUtil {

    private ConcurrentMapService concurrentMapService;
    public abstract Properties getConfigs() ;

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUPEPSUtil.class.getName());

    private ConcurrentMap<String, Boolean> antiReplayCache;

    public void setConcurrentMapService(ConcurrentMapService concurrentMapService) {
        this.concurrentMapService = concurrentMapService;
    }

    public ConcurrentMapService getConcurrentMapService() {
        return concurrentMapService;
    }

    public void setAntiReplayCache(ConcurrentMap<String, Boolean> antiReplayCache) {
        this.antiReplayCache = antiReplayCache;
    }

    public void flushReplayCache(){
        if (antiReplayCache != null){
            antiReplayCache.clear();
        }
    }

    /**
     * Method used to check if the saml request has not already been processed (replay attack)
     * @param samlId the SAMLID (uuid) processed
     * @param citizenCountryCode the citizen country code
     * @return true if the request has not yet been processed by the system
     */
    public Boolean checkNotPresentInCache(final String samlId, final String citizenCountryCode){
        if (antiReplayCache==null) {
            throw new STORKSAMLEngineRuntimeException("Bad configuration for the distributed cache, method should set the concurrentMap");
        }
        if (null != samlId){
            Boolean replayAttack = antiReplayCache.putIfAbsent(citizenCountryCode + "/" + samlId, Boolean.TRUE);

            if (null != replayAttack) {
                LOG.warn(LoggingMarkerMDC.SECURITY_WARNING, "Replay attack : Checking in PEPS antiReplayCache for samlId " + samlId + " ! ");
                return Boolean.FALSE;
            }
            LOG.debug("Checking in PEPS antiReplayCache for samlId " + samlId + " : ok");
        }
        return Boolean.TRUE;
    }

    public SAMLExtensionFormat getProtocolExtensionFormat(String messageFormatName){
        if(SAMLExtensionFormat.EIDAS10.getName().equalsIgnoreCase(messageFormatName)){
            return SAMLExtensionFormat.EIDAS10;
        } else {
            return SAMLExtensionFormat.STORK10;
        }
    }

    public boolean isEIDAS10(String messageFormatName){
        return (messageFormatName != null && SAMLExtensionFormat.EIDAS10.getName().equalsIgnoreCase(messageFormatName));
    }

    public Boolean isEidasMessageSupportedOnly(){
        return (Boolean.parseBoolean(this.getConfigs().getProperty(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString())));
    }

}
