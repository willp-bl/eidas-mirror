/* 
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */

package eu.stork.peps.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.InvalidPropertiesFormatException;
import java.util.Map;
import java.util.Properties;

import eu.stork.peps.auth.commons.PEPSErrors;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.exceptions.STORKSAMLEngineException;

/**
 * The Class InstanceCreator.
 * 
 * @author fjquevedo
 */
public final class ConfigurationCreator {

    /** The Constant LOGGER. */
    private static final Logger LOGGER = LoggerFactory
	    .getLogger(ConfigurationCreator.class.getName());

    /**
     * Creates the configuration.
     * 
     * @param instanceConfs the instance configuration
     * 
     * @return the map< string, map< string, object>>
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    public static Map<String, Map<String, Object>> createConfiguration(
	    final Map<String, InstanceEngine> instanceConfs) throws STORKSAMLEngineException {

	final Map<String, Map<String, Object>> instances = new HashMap<String, Map<String, Object>>();

	LOGGER.debug("Create configuration.");
	try {
	    // Only create instances for SAMLEngine configuration.
	    // INSTANCE
	    for (Map.Entry<String, InstanceEngine> entry : instanceConfs
		    .entrySet()) {
		final InstanceEngine iEngine = entry.getValue();

		final Map<String, Object> instance = new HashMap<String, Object>();

		// CONFIGURATION
		for (ConfigurationEngine configuration : iEngine
			.getConfiguration()) {
		    // Properties only for configuration SamlEngine.
		    if ("SamlEngineConf".equalsIgnoreCase(configuration.getName())) {
			instance.put(configuration.getName(),
					getNewInstance(configuration.getParameters()
							.get("fileConfiguration")));
		    } else {
			instance.put(configuration.getName(), configuration
					.getParameters());
		    }
		}
		instances.put(entry.getKey(), instance);
	    }
	} catch (STORKSAMLEngineException ex) {
	    LOGGER.error("Can not create instance from file configuration.");
	    throw new STORKSAMLEngineException(
				PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(),
				PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage(), ex);

	}
	return instances;
    }

    
    /**
     * Gets the new instance.
     * 
     * @param fileName the file name
     * 
     * @return the properties from the new instance
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine
     * runtime exception
     */
    private static Properties getNewInstance(final String fileName)
	    throws STORKSAMLEngineException {
	LOGGER.debug("Create file configuration properties to Stork Saml Engine.");
	InputStream fileEngineProp = null;
	try {
	    fileEngineProp = ConfigurationCreator.class
		    .getResourceAsStream("/" + fileName);
	    final Properties configuration = new Properties();
	    configuration.loadFromXML(fileEngineProp);	    
	    return configuration;
	} catch (InvalidPropertiesFormatException e) {
	    LOGGER.warn("Invalid properties format.");
		throw new STORKSAMLEngineException(
				PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(),
				PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage(), e);
	} catch (IOException e) {
	    LOGGER.error("Error read file: " + fileName);
		throw new STORKSAMLEngineException(
				PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(),
				PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage(), e);
	} finally {
	    IOUtils.closeQuietly(fileEngineProp);
	}
    }

    /**
     * Instantiates a new instance creator.
     */
    private ConfigurationCreator() {
    }
}