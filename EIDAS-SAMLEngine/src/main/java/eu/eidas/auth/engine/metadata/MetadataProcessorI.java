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

import javax.annotation.Nonnull;

import com.google.common.annotations.Beta;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;

import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.engine.exceptions.EIDASMetadataProviderException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import java.util.List;

/**
 * Obtains and processes SAML2 metadata objects associated with SAML requests and responses.
 *
 * @deprecated since 1.1, use {@link MetadataFetcherI} instead.
 */
@Deprecated
@Beta
public interface MetadataProcessorI {

    /**
     * @param url the url of the metadata file
     * @return the entity descriptor associated with the given url.
     * @throws throws EIDASMetadataProviderException
     */
    //TODO vargata
//    EntityDescriptor getEntityDescriptor(@Nonnull String url) throws EIDASMetadataProviderException;

/*
    /**
     * @param url the url of the metadata file
     * @return the first SPSSODescriptor found in the descriptor associated with the url
     * @throws EIDASMetadataProviderException
     */
    //TODO vargata
//    SPSSODescriptor getSPSSODescriptor(@Nonnull String url) throws EIDASMetadataProviderException;

    /**
     * @param url the url of the metadata file
     * @return the first IDPSSODescriptor found in the descriptor associated with the url
     * @throws EIDASMetadataProviderException
     */
    //TODO vargata
//    IDPSSODescriptor getIDPSSODescriptor(@Nonnull String url) throws EIDASMetadataProviderException;

    /**
     * check the signature of the descriptor found at the url
     *
     * @param url the url of the metadata file
     * @param engine the samlEngine instance used to validate the signature of the metadata file
     * @throws EIDASMetadataProviderException when the signature is not trusted by the engine
     */
    //TODO vargata
//    void checkValidMetadataSignature(@Nonnull String url, @Nonnull ProtocolEngineI engine) throws EIDASSAMLEngineException;

    void addListenerContentChanged( IStaticMetadataChangeListener listener);
    List<EntityDescriptorContainer> getEntityDescriptors();
}
