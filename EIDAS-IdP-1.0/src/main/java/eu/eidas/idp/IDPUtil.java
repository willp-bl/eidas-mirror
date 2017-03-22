package eu.eidas.idp;

import eu.eidas.auth.commons.EIDASUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Properties;

public final class IDPUtil {

    private static final Logger LOG = LoggerFactory.getLogger(IDPUtil.class);

    private static final Properties idpProperties = loadIDPConfigs();

    private static Properties loadConfigs(String path) throws IOException {
        Properties properties = new Properties();
        properties.load(IDPUtil.class.getClassLoader().getResourceAsStream(path));
        return properties;
    }

    public static Properties loadIDPConfigs() throws ApplicationSpecificIDPException {
        try {
            return IDPUtil.loadConfigs(Constants.IDP_PROPERTIES);
        } catch (IOException e) {
            LOG.error(e.getMessage());
            throw new ApplicationSpecificIDPException("Could not load configuration file", e);
        }
    }


    /**
     * @return metadata directory
     */
    public static String getMetadataRepositoryPath() {
        return idpProperties.getProperty(Constants.IDP_METADATA_REPOPATH);
    }

    /**
     * @return true when the metadata support should be active
     */
    public static boolean isMetadataHttpFetchEnabled() {
        return idpProperties.getProperty(Constants.IDP_METADATA_HTTPFETCH) == null || Boolean.parseBoolean(
                idpProperties.getProperty(Constants.IDP_METADATA_HTTPFETCH));
    }

    /**
     * @return true metadata signature must be validated for those not in trusted list
     */
    public static boolean isValidateEntityDescriptorSignatureEnabled() {
        Properties properties = IDPUtil.loadIDPConfigs();
        return properties.getProperty(Constants.IDP_METADATA_VALIDATESIGN) == null || Boolean.parseBoolean(
                properties.getProperty(Constants.IDP_METADATA_VALIDATESIGN));
    }

    public static String getTrustedEntityDescriptors() {
        Properties properties = IDPUtil.loadIDPConfigs();
        return properties.getProperty(Constants.IDP_METADATA_TRUSTEDDS, "");
    }


    private IDPUtil() {
    }
}
