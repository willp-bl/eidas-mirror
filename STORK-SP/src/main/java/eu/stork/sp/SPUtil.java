package eu.stork.sp;

import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.samlengineconfig.CertificateConfigurationManager;
import eu.stork.samlengineconfig.impl.CertificateManagerConfigurationImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.util.Properties;

public class SPUtil {
	static final Logger logger = LoggerFactory.getLogger(SPUtil.class.getName());
	private static final String SAML_ENGINE_LOCATION_VAR="STORKSP_CONF_LOCATION";

	private static Properties loadConfigs(String path) throws IOException
	{
		Properties properties = new Properties();
		properties.load(SPUtil.class.getClassLoader().getResourceAsStream(path));
		return properties;
	}

	public static Properties loadSPConfigs() throws ApplicationSpecificServiceException {
		try {
			return SPUtil.loadConfigs(Constants.SP_PROPERTIES);
		} catch (IOException e) {
			logger.error(e.getMessage());
			throw new ApplicationSpecificServiceException("Could not load configuration file", e.getMessage());
		}
	}

	/**
	 * @return true when the metadata support should be active
	 */
	public static boolean isMetadataEnabled(){
		return SPUtil.loadSPConfigs().getProperty(Constants.SP_METADATA_ACTIVATE)==null
				|| Boolean.parseBoolean(SPUtil.loadSPConfigs().getProperty(Constants.SP_METADATA_ACTIVATE));
	}
    static CertificateConfigurationManager spSamlEngineConfig=null;
	public static STORKSAMLEngine createSAMLEngine(String samlEngineName) throws STORKSAMLEngineException {
		if(spSamlEngineConfig==null && System.getenv(SAML_ENGINE_LOCATION_VAR)!=null){
			spSamlEngineConfig = ApplicationContextProvider.getApplicationContext().getBean(CertificateConfigurationManager.class);
			spSamlEngineConfig.setLocation(getLocation(System.getenv(SAML_ENGINE_LOCATION_VAR)));
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
