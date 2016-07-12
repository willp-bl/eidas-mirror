package eu.stork.idp;

import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.samlengineconfig.CertificateConfigurationManager;
import org.apache.log4j.Logger;

public class IDPUtil {
    /**
     * name of the property which switches idp metadata on and off
     */
    public static final String ACTIVE_METADATA_CHECK="idp.metadata.check";
    private static final Logger logger = Logger.getLogger(IDPUtil.class.getName());

    private static final String SAML_ENGINE_LOCATION_VAR="STORKIDP_CONF_LOCATION";
    static CertificateConfigurationManager spSamlEngineConfig=null;
    public static STORKSAMLEngine createSAMLEngine(String samlEngineName) throws STORKSAMLEngineException {
        if(spSamlEngineConfig==null && System.getenv(SAML_ENGINE_LOCATION_VAR)!=null){
            spSamlEngineConfig = ApplicationContextProvider.getApplicationContext().getBean(CertificateConfigurationManager.class);
            spSamlEngineConfig.setLocation(getLocation(System.getenv(SAML_ENGINE_LOCATION_VAR)));
            logger.info("retrieving config from "+System.getenv(SAML_ENGINE_LOCATION_VAR));
        }
        if(spSamlEngineConfig != null && spSamlEngineConfig.isActive() && spSamlEngineConfig.getConfiguration() != null && !spSamlEngineConfig.getConfiguration().isEmpty()){
            return STORKSAMLEngine.createSTORKSAMLEngine(samlEngineName,spSamlEngineConfig);
        }
        else {
            return STORKSAMLEngine.createSTORKSAMLEngine(samlEngineName);
        }

    }

    private static final String[] PATH_PREFIXES={"file://", "file:/","file:" };
    private static String getLocation(String location){
        if (location!=null){
            for(String prefix:PATH_PREFIXES){
                if(location.startsWith(prefix)){
                    return location.substring(prefix.length());
                }
            }
        }
        return location;
    }
}
