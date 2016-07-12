package eu.eidas.idp;

import java.util.Properties;

import javax.annotation.Nonnull;

import org.opensaml.saml2.metadata.EntityDescriptor;

import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.engine.metadata.MetadataSignerI;
import eu.eidas.auth.engine.metadata.impl.DefaultMetadataFetcher;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * IdpMetadataFetcher
 *
 * @since 1.1
 */
public final class IdpMetadataFetcher extends DefaultMetadataFetcher {

    private final Properties idpProperties = EIDASUtil.loadConfigs(Constants.IDP_PROPERTIES);

    @Nonnull
    @Override
    public EntityDescriptor getEntityDescriptor(@Nonnull String url, @Nonnull MetadataSignerI metadataSigner)
            throws EIDASSAMLEngineException {
        boolean checkMetadata = idpProperties != null && Boolean.parseBoolean(idpProperties.getProperty(IDPUtil.ACTIVE_METADATA_CHECK));
        if (checkMetadata) {
            return super.getEntityDescriptor(url, metadataSigner);
        }
        return null;
    }

    @Override
    protected boolean mustUseHttps() {
        return false;
    }

    @Override
    protected boolean mustValidateSignature(@Nonnull String url) {
        return false;
    }
}
