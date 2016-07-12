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

package eu.eidas.auth.engine.core.impl;

import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.engine.core.SAMLEngineEncryptionI;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class ModuleSignFactory.
 * 
 * @author fjquevedo
 * 
 */

public final class EncryptionModuleFactory {

    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory
	    .getLogger(EncryptionModuleFactory.class.getName());

    /**
     * Instantiates a new module sign factory.
     */
    private EncryptionModuleFactory() {

    }

    /**
     * Gets the single instance of EncryptionModuleFactory.
     *
     * @param className the class name
     *
     * @return single instance of EncryptionModuleFactory
     *
     * @throws eu.eidas.engine.exceptions.EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static SAMLEngineEncryptionI getInstance(final String className)
	    throws EIDASSAMLEngineException {
	LOG.debug("[START]EncryptionModuleFactory static");
	try {
	    final Class cls = Class.forName(className);
	    return (SAMLEngineEncryptionI) cls.newInstance();
	} catch (Exception e) {
	    throw new EIDASSAMLEngineException(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(),
				EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(),e);
	}

    }
}
