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
package eu.stork.peps.auth.engine.core;

import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.peps.exceptions.SAMLEngineException;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.security.credential.Credential;

import java.util.Properties;

/**
 * Created by bodabel on 10/12/2014.
 */
public interface SAMLEngineEncryptionI extends SAMLEngineModuleI {
    String DATA_ENCRYPTION_ALGORITHM="data.encryption.algorithm";
    String ENCRYPTION_ALGORITHM_WHITELIST="encryption.algorithm.whitelist";
    String RESPONSE_ENCRYPTION_MANDATORY="response.encryption.mandatory";

    void init(String fileConf) throws SAMLEngineException;

    void init(Properties propsConf) throws SAMLEngineException;

    /**
     *
     * @param authResponse
     * @param destinationCountryCode
     * @param requestIssuer the url of the metadataprovider of the request issuer
     * @return the encrypted response
     * @throws SAMLEngineException
     */
    Response encryptSAMLResponse(Response authResponse, String destinationCountryCode, String requestIssuer) throws SAMLEngineException;

    Response decryptSAMLResponse(Response authResponse,String countryCode) throws SAMLEngineException;

    boolean isModuleEncryptionEnable();

    boolean isEncryptionEnable(String countryCode);
    void setProperty(String propName, String propValue);

    Credential getEncryptionCredential() throws SAMLEngineException;
    void setMetadataProcessor(MetadataProcessorI procesor);

}
