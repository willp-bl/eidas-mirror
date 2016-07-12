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
package eu.stork.peps.auth.metadata;

import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.engine.AbstractSAMLEngine;
import eu.stork.peps.auth.engine.SAMLEngineUtils;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.peps.exceptions.SAMLEngineException;
import org.apache.commons.httpclient.HttpClient;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * check metadata
 * TODO:
 * 1. move perhaps in STORK-Specific module, since there is only a particular implementation
 */
public class PEPSMetadataProcessor implements MetadataProcessorI, IStaticMetadataChangeListener {
    private static final Logger LOG = LoggerFactory.getLogger(PEPSMetadataProcessor.class.getName());

    private static final int METADATA_TIMEOUT_MS=20000;
    private int metadataRequestTimeout;
    private IMetadataCachingService cache;
    private PEPSFileMetadataProcessor fileMetadataLoader;
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
        return helperGetEntity(url);
    }

    private EntityDescriptor helperGetEntity(String url) throws SAMLEngineException{
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
                PEPSHttpMetadataProvider provider = new PEPSHttpMetadataProvider(null, new HttpClient(), url);
                provider.setParserPool(AbstractSAMLEngine.getNewBasicSecuredParserPool());
                provider.initialize();
                //CAVEAT: the entity descriptor should have its id equal to the url (issuer url)
                entityDescriptor = provider.getEntityDescriptor(url);
                LOG.debug("Obtained entity descriptor from metadata retrieved from url " + url);
                if (entityDescriptor == null) {
                    LOG.info("Empty entity descriptor null from metadata retrieved from url " + url);
                }else{
                    putInCache(url, entityDescriptor);
                }
            } catch (MetadataProviderException mpe) {
                LOG.info("error getting a metadataprovider {}", mpe.getMessage());
                LOG.debug("error getting a metadataprovider {}", mpe);
                PEPSErrors error=expiredMetadata?PEPSErrors.SAML_ENGINE_INVALID_METADATA:PEPSErrors.SAML_ENGINE_NO_METADATA;
                throw new SAMLEngineException(error.errorCode(), error.errorMessage(), mpe);
            }
        }
        if(entityDescriptor==null ){
            throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_NO_METADATA.errorCode(), PEPSErrors.SAML_ENGINE_NO_METADATA.errorMessage());
        }
        if(!entityDescriptor.isValid()){
            throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_METADATA.errorCode(), PEPSErrors.SAML_ENGINE_INVALID_METADATA.errorMessage());
        }
        return entityDescriptor;

    }

    private boolean allowMetadataUrl(String url) throws SAMLEngineException{
        if(restrictHttp && (url==null || !url.toLowerCase().startsWith("https://"))){
            throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_METADATA_SOURCE.errorCode(), PEPSErrors.SAML_ENGINE_INVALID_METADATA_SOURCE.errorMessage());
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
        return getFirstRoleDescriptor(helperGetEntity(url), SPSSODescriptor.class);
    }

    @Override
    public IDPSSODescriptor getIDPSSODescriptor(String url) throws SAMLEngineException {
        return getFirstRoleDescriptor(helperGetEntity(url), IDPSSODescriptor.class);
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

    private int getMetadataTimeout(){
        return metadataRequestTimeout<=0?METADATA_TIMEOUT_MS:metadataRequestTimeout;
    }

    public int getMetadataRequestTimeout() {
        return metadataRequestTimeout;
    }

    public void setMetadataRequestTimeout(int metadataRequestTimeout) {
        this.metadataRequestTimeout = metadataRequestTimeout;
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
            List<EntityDescriptor> fileStoredDescriptors = getFileMetadataLoader().getEntityDescriptors();
            if(getCache()!=null){
                for(EntityDescriptor ed: fileStoredDescriptors){
                    getCache().putDescriptor(ed.getEntityID(), ed, EntityDescriptorType.STATIC);
                }
            }
            getFileMetadataLoader().addListenerContentChanged(this);
        }
    }

    public PEPSFileMetadataProcessor getFileMetadataLoader() {
        return fileMetadataLoader;
    }

    public void setFileMetadataLoader(PEPSFileMetadataProcessor fileMetadataLoader) {
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
    public void checkValidMetadataSignature(String url, STORKSAMLEngine engine) throws SAMLEngineException{
        if(isValidateEntityDescriptorSignature() && !getTrustedEntityDescriptorsSet().contains(url)) {
            EntityDescriptor entityDescriptor=getEntityDescriptor(url);
            SAMLEngineUtils.validateEntityDescriptorSignature(entityDescriptor, engine);
        }
    }

    @Override
    public void checkValidMetadataSignature(String url, KeyStore store) throws SAMLEngineException{
        if(isValidateEntityDescriptorSignature() && !getTrustedEntityDescriptorsSet().contains(url)) {
            EntityDescriptor entityDescriptor=getEntityDescriptor(url);
            SAMLEngineUtils.validateEntityDescriptorSignature(entityDescriptor, store);
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
        setTrustedEntityDescriptorsSet(PEPSUtil.parseSemicolonSeparatedList(trustedEntityDescriptors));
    }

    public Set<String> getTrustedEntityDescriptorsSet() {
        return trustedEntityDescriptorsSet;
    }

    public void setTrustedEntityDescriptorsSet(Set<String> trustedEntityDescriptorsList) {
        this.trustedEntityDescriptorsSet = trustedEntityDescriptorsList;
    }
}
