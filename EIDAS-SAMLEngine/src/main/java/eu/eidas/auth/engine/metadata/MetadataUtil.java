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

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.samlext.saml2mdattr.EntityAttributes;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;

import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.protocol.impl.SamlBindingUri;
import eu.eidas.auth.engine.core.eidas.EidasConstants;
import eu.eidas.auth.engine.core.eidas.SPType;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * Metadata related utilities.
 */
public final class MetadataUtil {

    @Nullable
    public static String getAssertionConsumerUrl(@Nullable SPSSODescriptor spSsoDescriptor) {
        if (spSsoDescriptor == null || spSsoDescriptor.getAssertionConsumerServices().isEmpty()) {
            return null;
        }
        for (AssertionConsumerService acs : spSsoDescriptor.getAssertionConsumerServices()) {
            if (acs.isDefault()) {
                return acs.getLocation();
            }
        }
        return spSsoDescriptor.getAssertionConsumerServices().get(0).getLocation();
    }

    /**
     * @since 1.1
     */
    @Nullable
    public static String getAssertionConsumerUrlFromMetadata(@Nonnull MetadataFetcherI metadataFetcher,
                                                             @Nonnull MetadataSignerI metadataSigner,
                                                             @Nonnull ILightRequest authnRequest)
            throws EIDASSAMLEngineException {
        String issuer = authnRequest.getIssuer();
        if (StringUtils.isNotBlank(issuer)) {
            // This would fetch the metadata only once!
            EntityDescriptor entityDescriptor = metadataFetcher.getEntityDescriptor(issuer, metadataSigner);
            SPSSODescriptor spSsoDescriptor = getSPSSODescriptor(entityDescriptor);
            return getAssertionConsumerUrl(spSsoDescriptor);
        }
        return null;
    }

    @Nullable
    private static <T extends RoleDescriptor> T getFirstRoleDescriptor(@Nonnull EntityDescriptor entityDescriptor,
                                                                       @Nonnull Class<T> clazz) {
        for (RoleDescriptor rd : entityDescriptor.getRoleDescriptors()) {
            if (clazz.isInstance(rd)) {
                return (T) rd;
            }
        }
        return null;
    }

    @Nullable
    public static IDPSSODescriptor getIDPSSODescriptor(@Nonnull EntityDescriptor entityDescriptor) {
        return getFirstRoleDescriptor(entityDescriptor, IDPSSODescriptor.class);
    }

    @Nullable
    public static SPSSODescriptor getSPSSODescriptor(@Nonnull EntityDescriptor entityDescriptor) {
        return getFirstRoleDescriptor(entityDescriptor, SPSSODescriptor.class);
    }

    /**
     * Retrieve SPType published in the metadata of the requesting party.
     *
     * @param entityDescriptor the entitity descriptor to use
     * @return the value of spType (either 'public' or 'private')
     */
    @Nullable
    public static String getSPTypeFromMetadata(@Nullable EntityDescriptor entityDescriptor) {
        if (entityDescriptor == null || entityDescriptor.getExtensions() == null) {
            return null;
        }
        List<XMLObject> spTypes = entityDescriptor.getExtensions().getUnknownXMLObjects(SPType.DEF_ELEMENT_NAME);
        final SPType type = (SPType) (spTypes.isEmpty() ? null : spTypes.get(0));
        return type == null ? null : type.getSPType();
    }

    /**
     * Returns the service LevelOfAssurance of a node
     *
     * @param entityDescriptor the EntityDescriptor instance
     * @return the LevelOfAssurance or the empty string.
     */
    public static String getServiceLevelOfAssurance(EntityDescriptor entityDescriptor) {
        String retrievedLevelOfAssurance = StringUtils.EMPTY;
        if (null == entityDescriptor) {
            return retrievedLevelOfAssurance;
        }
        for (XMLObject xmlObj : entityDescriptor.getExtensions().getUnknownXMLObjects()) {
            if (xmlObj instanceof EntityAttributes) {
                EntityAttributes eas = (EntityAttributes) xmlObj;
                for (Attribute attr : eas.getAttributes()) {
                    if (EidasConstants.LEVEL_OF_ASSURANCE_NAME.equalsIgnoreCase(attr.getName())
                            && !attr.getAttributeValues().isEmpty()) {
                        XSString val = (XSString) attr.getAttributeValues().get(0);
                        retrievedLevelOfAssurance = val.getValue();
                        break;
                    }
                }
                if (!StringUtils.isEmpty(retrievedLevelOfAssurance)) {
                    break;
                }
            }
        }
        return retrievedLevelOfAssurance;
    }

    @Nullable
    public static String getSingleSignOnUrl(@Nullable IDPSSODescriptor idpSsoDescriptor,
                                            @Nullable SamlBindingUri bindingUri) {
        if (idpSsoDescriptor == null || idpSsoDescriptor.getSingleSignOnServices().isEmpty()) {
            return null;
        }
        for (SingleSignOnService ssoService : idpSsoDescriptor.getSingleSignOnServices()) {
            String location = ssoService.getLocation();
            if (null == bindingUri) {
                return location;
            }
            if (bindingUri.getBindingUri().equals(ssoService.getBinding())) {
                return location;
            }
        }
        return idpSsoDescriptor.getSingleSignOnServices().get(0).getLocation();
    }

    private MetadataUtil() {
    }
}
