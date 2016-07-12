/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations 
 * under the License.
 */
package eu.eidas.auth.engine.metadata;

import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.engine.exceptions.SAMLEngineException;

/**
 * 
 * metadata related utilities
 *
 */
public class MetadataUtil {
    /**
     * Logger object.
     */
    protected static final Logger LOGGER = LoggerFactory.getLogger(MetadataUtil.class.getName());
	private MetadataUtil(){
		
	}
	
    public static String getAssertionUrlFromMetadata(MetadataProcessorI metadataProcessor, final EIDASSAMLEngine engine, final EIDASAuthnRequest authnRequest) throws EIDASSAMLEngineException{
    	String assertionUrl=null;
        if(!StringUtils.isEmpty(authnRequest.getIssuer())){
            try {
                metadataProcessor.checkValidMetadataSignature(authnRequest.getIssuer(), engine);
                SPSSODescriptor spDesc = metadataProcessor.getSPSSODescriptor(authnRequest.getIssuer());
                assertionUrl = getSPAssertionURL(spDesc);
            }catch(SAMLEngineException e){
                LOGGER.info("cannot retrieve assertion url from metadata at {} {}", authnRequest.getIssuer(), e);
                throw new EIDASSAMLEngineException(EIDASErrors.SAML_ENGINE_NO_METADATA.errorCode(), EIDASErrors.SAML_ENGINE_NO_METADATA.errorMessage());
            }
            
        }
        return assertionUrl;
    }
    private static String getSPAssertionURL(SPSSODescriptor spDesc){
        if(spDesc==null || spDesc.getAssertionConsumerServices().isEmpty())
            return null;
        String assertionUrl=spDesc.getAssertionConsumerServices().get(0).getLocation();
        for(AssertionConsumerService acs:spDesc.getAssertionConsumerServices()){
            if(acs.isDefault()){
                assertionUrl=acs.getLocation();
            }
        }
        return assertionUrl;
    }
	
}
