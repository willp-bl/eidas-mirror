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
package eu.eidas.node.auth.metadata;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.httpclient.HttpClient;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.SignableXMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.engine.AbstractProtocolEngine;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.auth.engine.metadata.MetadataSignerI;
import eu.eidas.engine.exceptions.EIDASMetadataProviderException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * retrieves and check metadata Retrieval: - support remote retrieval of EntityDescriptor objects - support local
 * (file-based) retrieval of either EntityDescriptor or EntitiesDescriptor objects Check: - remote or local
 * EntityDescriptor should be signed, with the following exceptions: - when they are in the list of explicitly trusted
 * ED or - signature check is disabled -see isValidateEntityDescriptorSignature or - are located inside an
 * EntityDescriptors contained, which should be signed - locally retrieved EntitiesDescriptor should be signed
 * <p>
 * TODO: 1. move perhaps in EIDAS-Specific module, since there is only a particular implementation
 * @deprecated since 1.1
 */
@Deprecated
@NotThreadSafe
public class NODEMetadataProcessor implements MetadataProcessorI, IStaticMetadataChangeListener {

    private static final Logger LOG = LoggerFactory.getLogger(NODEMetadataProcessor.class.getName());

    private static final int METADATA_TIMEOUT_MS = 20000;

    private int metadataRequestTimeout;

    private IMetadataCachingService cache;

    private NODEFileMetadataProcessor fileMetadataLoader;

    private boolean enableHttpRetrieval = false;

    /**
     * when restrictHttp is true, remote metadata is accepted only through https otherwise, metadata retrieved using
     * http protocol is also accepted
     */
    private boolean restrictHttp = false;

    /**
     * whether to enable the signature validation for EntityDescriptors
     */
    private boolean validateEntityDescriptorSignature = true;

    /**
     * initialized with a list of urls corresponding to EntityDescriptor not needing signature validation
     */
    private String trustedEntityDescriptors;

    private Set<String> trustedEntityDescriptorsSet = new HashSet<String>();

    public EntityDescriptor getEntityDescriptor(@Nonnull String url) throws EIDASMetadataProviderException {
        return helperGetEntityDescriptor(url);
    }

    public SignableXMLObject getEntityDescriptorSignatureHolder(@Nonnull String url)
            throws EIDASMetadataProviderException {
        return getCache().getDescriptorSignatureHolder(url);
    }

    private EntityDescriptor helperGetEntityDescriptor(@Nonnull String url) throws EIDASMetadataProviderException {
        EntityDescriptor entityDescriptor = getFromCache(url);
        boolean expiredMetadata = false;
        if (entityDescriptor != null && !entityDescriptor.isValid()) {
            LOG.error("Invalid static metadata information associated with " + url
                              + ", will try to retrieve from the network");
            entityDescriptor = null;
            expiredMetadata = true;
        }
        if (entityDescriptor == null && isHttpMetadataRetrieval() && allowMetadataUrl(url)) {
            try {
                LOG.debug("Trying to get metadata from url " + url);
                NODEHttpMetadataProvider provider = new NODEHttpMetadataProvider(null, new HttpClient(), url);
                provider.setParserPool(AbstractProtocolEngine.getSecuredParserPool());
                provider.initialize();
                XMLObject metadata = provider.getMetadata();
                if (metadata instanceof EntityDescriptor) {
                    entityDescriptor = (EntityDescriptor) metadata;
                } else {
                    //CAVEAT: the entity descriptor should have its id equal to the url (issuer url)
                    entityDescriptor = provider.getEntityDescriptor(url);
                }
                //entityDescriptor = provider.getEntityDescriptor(url);
                LOG.debug("Obtained entity descriptor from metadata retrieved from url " + url);
                if (entityDescriptor == null) {
                    LOG.info("Empty entity descriptor null from metadata retrieved from url " + url);
                } else {
                    putInCache(url, entityDescriptor);
                }
            } catch (MetadataProviderException mpe) {
                LOG.info("error getting a metadataprovider {}", mpe.getMessage());
                LOG.debug("error getting a metadataprovider {}", mpe);
                EidasErrorKey error = expiredMetadata ? EidasErrorKey.SAML_ENGINE_INVALID_METADATA
                                                      : EidasErrorKey.SAML_ENGINE_NO_METADATA;
                throw new EIDASMetadataProviderException(error.errorCode(), error.errorMessage(), mpe);
            }
        }
        if (entityDescriptor == null) {
            throw new EIDASMetadataProviderException(EidasErrorKey.SAML_ENGINE_NO_METADATA.errorCode(),
                                                     EidasErrorKey.SAML_ENGINE_NO_METADATA.errorMessage(),
                                                     "No entity descriptor for URL " + url);
        }
        if (!entityDescriptor.isValid()) {
            throw new EIDASMetadataProviderException(EidasErrorKey.SAML_ENGINE_INVALID_METADATA.errorCode(),
                                                     EidasErrorKey.SAML_ENGINE_INVALID_METADATA.errorMessage(),
                                                     "Invalid entity descriptor for URL " + url);
        }
        return entityDescriptor;

    }

    private boolean allowMetadataUrl(@Nonnull String url) throws EIDASMetadataProviderException {
        if (restrictHttp && !url.toLowerCase(Locale.ENGLISH).startsWith("https://")) {
            throw new EIDASMetadataProviderException(EidasErrorKey.SAML_ENGINE_INVALID_METADATA_SOURCE.errorCode(),
                                                     EidasErrorKey.SAML_ENGINE_INVALID_METADATA_SOURCE.errorMessage(),
                                                     "Metadata URL is not secure : " + url);
        }
        return true;
    }

    private <T extends RoleDescriptor> T getFirstRoleDescriptor(EntityDescriptor entityDescriptor,
                                                                final Class<T> clazz) {
        for (RoleDescriptor rd : entityDescriptor.getRoleDescriptors()) {
            if (clazz.isInstance(rd)) {
                return (T) rd;
            }
        }
        return null;
    }

    @Override
    public SPSSODescriptor getSPSSODescriptor(@Nonnull String url) throws EIDASMetadataProviderException {
        return getFirstRoleDescriptor(helperGetEntityDescriptor(url), SPSSODescriptor.class);
    }

    @Override
    public IDPSSODescriptor getIDPSSODescriptor(@Nonnull String url) throws EIDASMetadataProviderException {
        return getFirstRoleDescriptor(helperGetEntityDescriptor(url), IDPSSODescriptor.class);
    }

    private EntityDescriptor getFromCache(String url) {
        if (cache != null) {
            return cache.getDescriptor(url);
        }
        return null;
    }

    private void putInCache(String url, EntityDescriptor ed) {
        if (cache != null && ed != null && ed.isValid()) {
            cache.putDescriptor(url, ed, EntityDescriptorType.DYNAMIC);
        }
    }

    public IMetadataCachingService getCache() {
        return cache;
    }

    public void setCache(IMetadataCachingService cache) {
        this.cache = cache;
    }

    /**
     * perform post construct task, eg populating the cache with file based metadata
     */
    public void initProcessor() {
        if (getFileMetadataLoader() != null) {
            List<EntityDescriptorContainer> fileStoredDescriptors = getFileMetadataLoader().getEntityDescriptors();
            if (getCache() != null) {
                for (EntityDescriptorContainer edc : fileStoredDescriptors) {
                    for (EntityDescriptor ed : edc.getEntityDescriptors()) {
                        getCache().putDescriptor(ed.getEntityID(), ed, EntityDescriptorType.STATIC);
                        if (edc.getEntitiesDescriptor() != null && ed.getSignature() == null) {
                            getCache().putDescriptorSignatureHolder(ed.getEntityID(), edc);
                        }
                    }
                }
            }
            getFileMetadataLoader().addListenerContentChanged(this);
        }
    }

    public NODEFileMetadataProcessor getFileMetadataLoader() {
        return fileMetadataLoader;
    }

    public void setFileMetadataLoader(NODEFileMetadataProcessor fileMetadataLoader) {
        this.fileMetadataLoader = fileMetadataLoader;
    }

    private boolean isHttpMetadataRetrieval() {
        return isEnableHttpRetrieval();
    }

    public boolean isEnableHttpRetrieval() {
        return enableHttpRetrieval;
    }

    public void setEnableHttpRetrieval(boolean enableHttpRetrieval) {
        this.enableHttpRetrieval = enableHttpRetrieval;
    }

    public boolean isRestrictHttp() {
        return restrictHttp;
    }

    public void setRestrictHttp(boolean restrictHttp) {
        this.restrictHttp = restrictHttp;
    }

    @Override
    public void add(EntityDescriptor ed) {
        if (getCache() != null) {
            getCache().putDescriptor(ed.getEntityID(), ed, EntityDescriptorType.STATIC);
        }
    }

    @Override
    public void remove(String entityID) {
        if (getCache() != null) {
            getCache().putDescriptor(entityID, null, null);
        }
    }

    @Override
    public void checkValidMetadataSignature(@Nonnull String url, @Nonnull ProtocolEngineI engine)
            throws EIDASSAMLEngineException {
        if (isValidateEntityDescriptorSignature() && !getTrustedEntityDescriptorsSet().contains(url)) {
            //TODO quick fix to overcome runtime exception EIDASSAMLEngineException("invalid entity descriptor") thrown from SAMLEngineUtils#validateEntityDescriptorSignature
            SignableXMLObject entityDescriptor = helperGetEntityDescriptor(url);
            MetadataSignerI signer = (MetadataSignerI) engine.getSigner();
            signer.validateMetadataSignature(entityDescriptor);
        }
    }

    public boolean isValidateEntityDescriptorSignature() {
        return validateEntityDescriptorSignature;
    }

    public void setValidateEntityDescriptorSignature(boolean validateEntityDescriptorSignature) {
        this.validateEntityDescriptorSignature = validateEntityDescriptorSignature;
    }

    public String getTrustedEntityDescriptors() {
        return trustedEntityDescriptors;
    }

    public void setTrustedEntityDescriptors(String trustedEntityDescriptors) {
        this.trustedEntityDescriptors = trustedEntityDescriptors;
        setTrustedEntityDescriptorsSet(EIDASUtil.parseSemicolonSeparatedList(trustedEntityDescriptors));
    }

    public Set<String> getTrustedEntityDescriptorsSet() {
        return trustedEntityDescriptorsSet;
    }

    public void setTrustedEntityDescriptorsSet(Set<String> trustedEntityDescriptorsList) {
        this.trustedEntityDescriptorsSet = trustedEntityDescriptorsList;
    }

    public int getMetadataRequestTimeout() {
        return metadataRequestTimeout;
    }

    public void setMetadataRequestTimeout(int metadataRequestTimeout) {
        this.metadataRequestTimeout = metadataRequestTimeout;
    }
}
