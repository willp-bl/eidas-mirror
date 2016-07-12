/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
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

import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.core.SAMLEngineModuleI;
import eu.eidas.engine.exceptions.SAMLEngineException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;

public class AbstractSAMLEngineModule implements SAMLEngineModuleI{
    /**
     * The logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AbstractSAMLEngineModule.class.getName());
    /**
     * Gets the properties.
     *
     * @return the properties
     */
    public Properties getProperties() {
        return properties;
    }

    /**
     * Sets the properties.
     *
     * @param newProperties the new properties
     */
    public void setProperties(final Properties newProperties) {
        this.properties = newProperties;
    }

    /** The HW sign prop. */
    private Properties properties = null;

    public void setProperty(String propName, String propValue){
        if(properties!=null) {
            properties.setProperty(propName, propValue);
        }
    }


    private Boolean checkIssuer = null;

    public void checkCertificateIssuer(X509Certificate certificate) throws SAMLEngineException {
        if (null == checkIssuer) {
            checkIssuer = getProperties()==null?Boolean.FALSE:Boolean.parseBoolean(getProperties().getProperty(SELF_SIGNED_PROPERTY));
        }
        if (checkIssuer && SAMLEngineUtils.isCertificateSelfSigned(certificate)) {
            LOG.info("ERROR : The certificate with reference '{}' failed check (selfsigned)", certificate.getIssuerDN());
            throw new SAMLEngineException(EIDASErrors.INVALID_CERTIFICATE_SIGN.errorCode(), EIDASErrors.INVALID_CERTIFICATE_SIGN.errorMessage());
        }
    }

    private Boolean checkTemporalValidity = null;


    public void checkCertificateValidityPeriod(X509Certificate certificate) throws SAMLEngineException {
        if (null == checkTemporalValidity) {
            checkTemporalValidity = getProperties()==null?Boolean.FALSE:Boolean.parseBoolean(getProperties().getProperty(CHECK_VALIDITY_PERIOD_PROPERTY));
        }
        if (checkTemporalValidity) {
            Date notBefore = certificate.getNotBefore();
            Date notAfter = certificate.getNotAfter();
            Date currentDate = Calendar.getInstance().getTime();
            if (currentDate.before(notBefore) || currentDate.after(notAfter)) {
                LOG.info("ERROR : The certificate with reference '{}' failed check (out of date)", certificate.getIssuerDN());
                throw new SAMLEngineException(EIDASErrors.INVALID_CERTIFICATE_SIGN.errorCode(), EIDASErrors.INVALID_CERTIFICATE_SIGN.errorMessage());
            }
        }
    }




}
