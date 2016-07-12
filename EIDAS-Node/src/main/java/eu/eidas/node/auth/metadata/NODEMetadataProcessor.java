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

import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.engine.AbstractSAMLEngine;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.engine.exceptions.SAMLEngineException;

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

import java.security.KeyStore;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * retrieves and check metadata
 * Retrieval: 
 * - support remote retrieval of EntityDescriptor objects
 * - support local (file-based) retrieval of either EntityDescriptor or EntitiesDescriptor objects
 * Check:
 * - remote or local EntityDescriptor should be signed, with the following exceptions:
 *     - when they are in the list of explicitly trusted ED or 
 *     - signature check is disabled -see isValidateEntityDescriptorSignature or
 *     - are located inside an EntityDescriptors contained, which should be signed
 * - locally retrieved EntitiesDescriptor should be signed
 * 
 * TODO:
 * 1. move perhaps in EIDAS-Specific module, since there is only a particular implementation
 */
public class NODEMetadataProcessor implements MetadataProcessorI, IStaticMetadataChangeListener {
    private static final Logger LOG = LoggerFactory.getLogger(NODEMetadataProcessor.class.getName());

    private static final int METADATA_TIMEOUT_MS=20000;
    private int metadataRequestTimeout;
    private IMetadataCachingService cache;
    private NODEFileMetadataProcessor fileMetadataLoader;
    private boolean enableHttpRetrieval=false;
    /**
     * when restrictHttp is true, remote metadata is accepted only through https
     * otherwise, metadata retrieved using http protocol is also accepted
     */
    private boolean restrictHttp=false;
    /**
     * whether to enable the signature validation for EntityDescriptors
     */
    private boolean validateEntityDescriptorSignature=true;
    /**
     * initialized with a list of urls corresponding to EntityDescriptor not needing signature validation
     */
    private String trustedEntityDescriptors;
    private Set<String> trustedEntityDescriptorsSet=new HashSet<String>();


    public EntityDescriptor getEntityDescriptor(String url) throws SAMLEngineException{
        return helperGetEntityDescriptor(url);
    }

    public SignableXMLObject getEntityDescriptorSignatureHolder(String url) throws SAMLEngineException{
        return getCache().getDescriptorSignatureHolder(url);
    }

    private EntityDescriptor helperGetEntityDescriptor(String url) throws SAMLEngineException{
        EntityDescriptor entityDescriptor=null;
        if(url==null || url.isEmpty()){
            if(LOG.isTraceEnabled()) {
                LOG.trace("metadata retrieving from "+url+" is disabled");
            }
            return null;
        }
        entityDescriptor=getFromCache(url);
        boolean expiredMetadata=false;
        if(entityDescriptor!=null && !entityDescriptor.isValid()){
            LOG.error("Invalid static metadata information associated with "+url+", will try to retrieve from the network");
            entityDescriptor=null;
            expiredMetadata=true;
        }
        if(entityDescriptor==null && isHttpMetadataRetrieval() && allowMetadataUrl(url)) {
            try {
                LOG.debug("Trying to get metadata from url " + url);
                NODEHttpMetadataProvider provider = new NODEHttpMetadataProvider(null, new HttpClient(), url);
                provider.setParserPool(AbstractSAMLEngine.getNewBasicSecuredParserPool());
                provider.initialize();
                XMLObject metadata = provider.getMetadata();
                if(metadata instanceof EntityDescriptor) {
                    entityDescriptor = (EntityDescriptor)metadata;
                }else {
                    //CAVEAT: the entity descriptor should have its id equal to the url (issuer url)
                    entityDescriptor=provider.getEntityDescriptor(url);
                }
                //entityDescriptor = provider.getEntityDescriptor(url);
                LOG.debug("Obtained entity descriptor from metadata retrieved from url " + url);
                if (entityDescriptor == null) {
                    LOG.info("Empty entity descriptor null from metadata retrieved from url " + url);
                }else{
                    putInCache(url, entityDescriptor);
                }
            } catch (MetadataProviderException mpe) {
                LOG.info("error getting a metadataprovider {}", mpe.getMessage());
                LOG.debug("error getting a metadataprovider {}", mpe);
                EIDASErrors error=expiredMetadata?EIDASErrors.SAML_ENGINE_INVALID_METADATA:EIDASErrors.SAML_ENGINE_NO_METADATA;
                throw new SAMLEngineException(error.errorCode(), error.errorMessage(), mpe);
            }
        }
        if(entityDescriptor==null ){
            throw new SAMLEngineException(EIDASErrors.SAML_ENGINE_NO_METADATA.errorCode(), EIDASErrors.SAML_ENGINE_NO_METADATA.errorMessage());
        }
        if(!entityDescriptor.isValid()){
            throw new SAMLEngineException(EIDASErrors.SAML_ENGINE_INVALID_METADATA.errorCode(), EIDASErrors.SAML_ENGINE_INVALID_METADATA.errorMessage());
        }
        return entityDescriptor;

    }

    private boolean allowMetadataUrl(String url) throws SAMLEngineException{
        if(restrictHttp && (url==null || !url.toLowerCase().startsWith("https://"))){
            throw new SAMLEngineException(EIDASErrors.SAML_ENGINE_INVALID_METADATA_SOURCE.errorCode(), EIDASErrors.SAML_ENGINE_INVALID_METADATA_SOURCE.errorMessage());
        }
        return true;
    }
    private <T extends RoleDescriptor> T getFirstRoleDescriptor(EntityDescriptor entityDescriptor, final Class<T> clazz){
        for(RoleDescriptor rd:entityDescriptor.getRoleDescriptors()){
            if(clazz.isInstance(rd)){
                return (T)rd;
            }
        }
        return null;
    }

    @Override
    public SPSSODescriptor getSPSSODescriptor(String url) throws SAMLEngineException {
        return getFirstRoleDescriptor(helperGetEntityDescriptor(url), SPSSODescriptor.class);
    }

    @Override
    public IDPSSODescriptor getIDPSSODescriptor(String url) throws SAMLEngineException {
        return getFirstRoleDescriptor(helperGetEntityDescriptor(url), IDPSSODescriptor.class);
    }

    private EntityDescriptor getFromCache(String url) throws SAMLEngineException{
        if(cache!=null){
            return cache.getDescriptor(url);
        }
        return null;
    }

    private void putInCache(String url, EntityDescriptor ed){
        if(cache!=null && ed!=null && ed.isValid()){
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
    public void initProcessor(){
        if(getFileMetadataLoader()!=null){
            List<EntityDescriptorContainer> fileStoredDescriptors = getFileMetadataLoader().getEntityDescriptors();
            if(getCache()!=null){
                for(EntityDescriptorContainer edc: fileStoredDescriptors){
                	for(EntityDescriptor ed:edc.getEntityDescriptors()){
                		getCache().putDescriptor(ed.getEntityID(), ed, EntityDescriptorType.STATIC);
                		if(edc.getEntitiesDescriptor()!=null && ed.getSignature()==null){
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

    private boolean isHttpMetadataRetrieval(){
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
        if(getCache()!=null){
            getCache().putDescriptor(ed.getEntityID(), ed, EntityDescriptorType.STATIC);
        }
    }

    @Override
    public void remove(String entityID) {
        if(getCache()!=null){
            getCache().putDescriptor(entityID, null, null);
        }
    }

    @Override
    public void checkValidMetadataSignature(String url, EIDASSAMLEngine engine) throws SAMLEngineException{
        if(isValidateEntityDescriptorSignature() && !getTrustedEntityDescriptorsSet().contains(url)) {
            SignableXMLObject entityDescriptor=getEntityDescriptorSignatureHolder(url);
            SAMLEngineUtils.validateEntityDescriptorSignature(entityDescriptor, engine);
        }
    }

    @Override
    public void checkValidMetadataSignature(String url, KeyStore store) throws SAMLEngineException{
        if(isValidateEntityDescriptorSignature() && !getTrustedEntityDescriptorsSet().contains(url)) {
        	SignableXMLObject obj=getEntityDescriptorSignatureHolder(url);
            SAMLEngineUtils.validateEntityDescriptorSignature(obj, store);
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
