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
package eu.eidas.idp;

import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.metadata.SimpleMetadataProcessor;
import eu.eidas.engine.exceptions.SAMLEngineException;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.util.Properties;

/**
 * check metadata
 * */
public class IdPMetadataProcessor extends SimpleMetadataProcessor {
    private static final Logger LOG = LoggerFactory.getLogger(IdPMetadataProcessor.class.getName());

    private Properties idpProperties = EIDASUtil.loadConfigs(Constants.IDP_PROPERTIES);


    public EntityDescriptor getEntityDescriptor(String url){
        EntityDescriptor entityDescriptor=null;
        boolean checkMetadata=false;
        if(idpProperties!=null && Boolean.parseBoolean(idpProperties.getProperty(IDPUtil.ACTIVE_METADATA_CHECK))){
            checkMetadata=true;
        }
        if(checkMetadata) {
            entityDescriptor=getEntityDescriptorHelper(url);
        }
        return entityDescriptor;
    }

    @Override
    public SPSSODescriptor getSPSSODescriptor(String url) throws SAMLEngineException {
        return getFirstRoleDescriptor(getEntityDescriptor(url), SPSSODescriptor.class);
    }

    @Override
    public IDPSSODescriptor getIDPSSODescriptor(String url) throws SAMLEngineException {
        return null;
    }

    @Override
    public void checkValidMetadataSignature(String url, EIDASSAMLEngine engine) throws SAMLEngineException {
        //not implemented
    	LOG.warn("MetadataProcessor in demo IdP does not actually checkk the signature of metadataa");
    }
    @Override
    public void checkValidMetadataSignature(String url, KeyStore store) throws SAMLEngineException {
        //not implemented
    }
}
