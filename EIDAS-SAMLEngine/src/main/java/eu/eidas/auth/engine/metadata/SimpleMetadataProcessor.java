package eu.eidas.auth.engine.metadata;


import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.engine.exceptions.SAMLEngineException;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;


public abstract class SimpleMetadataProcessor implements MetadataProcessorI {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleMetadataProcessor.class.getName());

    private static final int METADATA_TIMEOUT_MS=20000;


    public abstract EntityDescriptor getEntityDescriptor(String url);

    protected EntityDescriptor getEntityDescriptorHelper(String url){
        EntityDescriptor entityDescriptor=null;
        try {
            HTTPMetadataProvider provider = new SimpleHttpMetadataProvider(url, METADATA_TIMEOUT_MS);
            provider.setParserPool(new BasicParserPool());
            provider.initialize();
            if (StringUtils.isNotEmpty(url)) {
                entityDescriptor = provider.getEntityDescriptor(url);
            } else {
                throw new MetadataProviderException("the metadata url parameter is null or empty");
            }
        } catch (MetadataProviderException mpe) {
            LOG.error("error getting a metadataprovider {}", mpe);
        }
        return entityDescriptor;
    }

    private class SimpleHttpMetadataProvider extends HTTPMetadataProvider{
        public SimpleHttpMetadataProvider(String url, int timeout) throws MetadataProviderException{
            super(url, timeout);
        }
        protected void releaseMetadataDOM(XMLObject metadata){//NOSONAR
            //do not release DOM information
        }
    }
    protected <T extends RoleDescriptor> T getFirstRoleDescriptor(EntityDescriptor entityDescriptor, final Class<T> clazz){
        for(RoleDescriptor rd:entityDescriptor.getRoleDescriptors()){
            if(clazz.isInstance(rd)){
                return (T)rd;
            }
        }
        return null;
    }

    @Override
    public abstract SPSSODescriptor getSPSSODescriptor(String url) throws SAMLEngineException;

    @Override
    public abstract IDPSSODescriptor getIDPSSODescriptor(String url) throws SAMLEngineException ;

    @Override
    public void checkValidMetadataSignature(String url, EIDASSAMLEngine engine) throws SAMLEngineException {
        //not implemented
        LOG.warn("Simple MetadataProcessor does not actually check the signature of metadata");
    }
    @Override
    public void checkValidMetadataSignature(String url, KeyStore store) throws SAMLEngineException {
        //not implemented
        LOG.warn("Simple MetadataProcessor does not actually check the signature of metadata");
    }
}

