package eu.eidas.idp;

import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.samlengineconfig.CertificateConfigurationManager;

import org.apache.log4j.Logger;

public class IDPUtil {
    /**
     * name of the property which switches idp metadata on and off
     */
    public static final String ACTIVE_METADATA_CHECK="idp.metadata.check";
    private static final Logger logger = Logger.getLogger(IDPUtil.class.getName());

    private static final String SAML_ENGINE_LOCATION_VAR="IDP_CONF_LOCATION";
    static CertificateConfigurationManager idpSamlEngineConfig=null;
    public static EIDASSAMLEngine createSAMLEngine(String samlEngineName) throws EIDASSAMLEngineException {
        if(idpSamlEngineConfig==null && System.getenv(SAML_ENGINE_LOCATION_VAR)!=null){
            idpSamlEngineConfig = ApplicationContextProvider.getApplicationContext().getBean(CertificateConfigurationManager.class);
            idpSamlEngineConfig.setLocation(getLocation(System.getenv(SAML_ENGINE_LOCATION_VAR)));
            logger.info("retrieving config from "+System.getenv(SAML_ENGINE_LOCATION_VAR));
        }
        if(idpSamlEngineConfig != null && idpSamlEngineConfig.isActive() && idpSamlEngineConfig.getConfiguration() != null && !idpSamlEngineConfig.getConfiguration().isEmpty()){
            return EIDASSAMLEngine.createSAMLEngine(samlEngineName,idpSamlEngineConfig);
        }
        else {
            return EIDASSAMLEngine.createSAMLEngine(samlEngineName);
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
