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
package eu.stork.peps.auth.engine.metadata;

import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.SAMLEngineException;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;

import java.security.KeyStore;

/**
 * obtain and processes metadata associated with SAML requests and responses
 */
public interface MetadataProcessorI {
    /**
     *
     * @param url
     * @return the entity descriptor associated with the given url.
     * @throws SAMLEngineException
     */
    EntityDescriptor getEntityDescriptor(String url) throws SAMLEngineException;
    /**
     *
     * @param url
     * @return the first SPSSODescriptor found in the descriptor associated with the url
     * @throws SAMLEngineException
     */
    SPSSODescriptor getSPSSODescriptor(String url) throws SAMLEngineException;
    /**
     *
     * @param url
     * @return the first IDPSSODescriptor found in the descriptor associated with the url
     * @throws SAMLEngineException
     */
    IDPSSODescriptor getIDPSSODescriptor(String url) throws SAMLEngineException;

    /**
     * check the signature of the descriptor found at the url
     * @param url
     * @param engine
     * @throws SAMLEngineException when the signature is not trusted by the engine
     */
    void checkValidMetadataSignature(String url, STORKSAMLEngine engine) throws SAMLEngineException;

    /**
     * check the signature of the descriptor found at the url
     * @param url
     * @param trustStore
     * @throws SAMLEngineException when the signature is not trusted by the keystore
     */
    void checkValidMetadataSignature(String url, KeyStore trustStore) throws SAMLEngineException;

}
