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
package eu.stork.idp;

import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.peps.exceptions.SAMLEngineException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.util.Properties;
import java.util.Timer;

/**
 * check metadata
 * */
public class IdPMetadataProcessor implements MetadataProcessorI {
    private static final Logger LOG = LoggerFactory.getLogger(IdPMetadataProcessor.class.getName());

    private static final int METADATA_TIMEOUT_MS=20000;
    private Properties idpProperties = PEPSUtil.loadConfigs(Constants.IDP_PROPERTIES);


    public EntityDescriptor getEntityDescriptor(String url){
        EntityDescriptor entityDescriptor=null;
        boolean checkMetadata=false;
        if(idpProperties!=null && Boolean.parseBoolean(idpProperties.getProperty(IDPUtil.ACTIVE_METADATA_CHECK))){
            checkMetadata=true;
        }
        if(checkMetadata) {
            try {
                HTTPMetadataProvider provider = new IdPHttpMetadataProvider(url, METADATA_TIMEOUT_MS);
                provider.setParserPool(new BasicParserPool());
                provider.initialize();
                if (StringUtils.isNotEmpty(url)) {
                    entityDescriptor = provider.getEntityDescriptor(url);
                } else {
                    throw new  MetadataProviderException("the metadata url parameter is null or empty");
                }
            } catch (MetadataProviderException mpe) {
                LOG.error("error getting a metadataprovider {}", mpe);
            }
        }
        return entityDescriptor;
    }
    private class IdPHttpMetadataProvider extends HTTPMetadataProvider{
        public IdPHttpMetadataProvider(String url, int timeout) throws MetadataProviderException{
            super(url, timeout);
        }
        protected void releaseMetadataDOM(XMLObject metadata){//NOSONAR
            //do not release DOM information
        }
    }

    @Override
    public SPSSODescriptor getSPSSODescriptor(String url) throws SAMLEngineException {
        return null;
    }

    @Override
    public IDPSSODescriptor getIDPSSODescriptor(String url) throws SAMLEngineException {
        return null;
    }

    @Override
    public void checkValidMetadataSignature(String url, STORKSAMLEngine engine) throws SAMLEngineException {
        //not implemented
    }
    @Override
    public void checkValidMetadataSignature(String url, KeyStore store) throws SAMLEngineException {
        //not implemented
    }
}
