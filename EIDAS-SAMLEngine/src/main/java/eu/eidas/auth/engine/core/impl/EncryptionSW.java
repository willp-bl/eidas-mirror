/*
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */

package eu.eidas.auth.engine.core.impl;

import java.security.cert.X509Certificate;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.google.common.collect.ImmutableMap;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.io.ReloadableProperties;
import eu.eidas.auth.engine.configuration.dom.EncryptionKey;
import eu.eidas.auth.engine.xml.opensaml.CertificateUtil;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

public final class EncryptionSW extends KeyStoreSamlEngineEncryption {

    /**
     * The logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(EncryptionSW.class);

    private static ReloadableProperties initActivationConf(Map<String, String> properties) {
        String activationConfigurationFile = EncryptionKey.ENCRYPTION_ACTIVATION.getAsString(properties);
        LOG.debug("File containing encryption configuration: \"" + activationConfigurationFile + "\"");
        return new ReloadableProperties(activationConfigurationFile);
    }

    private final ImmutableMap<String, String> properties;

    /**
     * Encryption configurations for the engine. Specify to use encryption/decryption for the instances
     */
    private final ReloadableProperties encryptionActivationProperties;

    public EncryptionSW(Map<String, String> properties) throws EIDASSAMLEngineException {
        super(properties);
        this.properties = ImmutableMap.copyOf(properties);
        encryptionActivationProperties = initActivationConf(properties);
    }

    /**
     * Returns the encryption certificate to be used to encrypt a response for the given country
     *
     * @return the encryption certificate to be used to encrypt a response for the given country
     */
    @Override
    @Nullable
    public X509Certificate getEncryptionCertificate(@Nullable String destinationCountryCode)
            throws EIDASSAMLEngineException {
        if (isEncryptionEnabled(destinationCountryCode)) {
            String issuerKey = new StringBuilder(EncryptionKey.RESPONSE_TO_POINT_ISSUER_PREFIX.getKey()).append(
                    destinationCountryCode).toString();
            String serialNumberKey =
                    new StringBuilder(EncryptionKey.RESPONSE_TO_POINT_SERIAL_NUMBER_PREFIX.getKey()).append(
                            destinationCountryCode).toString();
            String serialNumber = properties.get(serialNumberKey);
            String responseToPointIssuer = properties.get(issuerKey);
            if (StringUtils.isNotBlank(responseToPointIssuer)) {
                for (final X509Certificate certificate : getEncryptionCertificates()) {
                    if (CertificateUtil.matchesCertificate(serialNumber, responseToPointIssuer, certificate)) {

                        if (isDisallowedSelfSignedCertificate()) {
                            CertificateValidator.checkCertificateIssuer(certificate);
                        }
                        if (isCheckedValidityPeriod()) {
                            CertificateValidator.checkCertificateValidityPeriod(certificate);
                        }

                        return certificate;
                    }
                }
                throw new EIDASSAMLEngineException(EidasErrorKey.SAML_ENGINE_INVALID_CERTIFICATE.errorCode(),
                                                   EidasErrorKey.SAML_ENGINE_INVALID_CERTIFICATE.errorMessage());
            } else {
                LOG.error("Encryption of SAML Response NOT done, because no \"" + issuerKey +
                                  "\" configured!");
            }
        }
        return null;
    }

    private boolean isEnabled(String key) {
        boolean value = false;
        if (null != encryptionActivationProperties) {
            try {
                value = Boolean.parseBoolean(encryptionActivationProperties.getProperties().getProperty(key));
            } catch (Exception e) {
                LOG.info("ERROR : Error retrieving activation value. {}", e);
            }
        }
        LOG.debug("Is active for: " + key + " : " + value);
        return value;
    }

    @Override
    public boolean isEncryptionEnabled(@Nonnull String countryCode) {
        LOG.debug("Loading encryption configuration");
        if (isResponseEncryptionMandatory()) {
            return true;
        }
        if (StringUtils.isEmpty(countryCode)) {
            LOG.info("ERROR : Country code is empty!");
            return false;
        } else {
            return isEnabled(EncryptionKey.ENCRYPT_TO_PREFIX.getKey() + countryCode);
        }
    }
}
