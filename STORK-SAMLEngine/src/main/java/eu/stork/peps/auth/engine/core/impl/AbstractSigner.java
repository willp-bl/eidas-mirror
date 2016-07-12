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

package eu.stork.peps.auth.engine.core.impl;

import eu.stork.peps.auth.engine.CertificateAliasPair;
import eu.stork.peps.auth.engine.SAMLEngineUtils;
import eu.stork.peps.auth.engine.core.SAMLEngineSignI;
import eu.stork.peps.exceptions.SAMLEngineException;
import org.opensaml.Configuration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Properties;

/**
 * common signer behavior
 */
public abstract class AbstractSigner extends AbstractSAMLEngineModule implements SAMLEngineSignI {
    /**
     * The logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AbstractSigner.class.getName());

    @Override
    public void init(Properties props) throws SAMLEngineException {
        setProperties(props);
    }
    protected String getSignatureAlgorithmForSign() {
        return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
    }

    public Credential getSigningCredential(KeyStore keystore) throws SAMLEngineException{
        try {
            final String serialNumber = getProperties().getProperty("serialNumber");
            final String issuer = getProperties().getProperty("issuer");
            CertificateAliasPair certificatePair = SAMLEngineUtils.getCertificatePair(keystore, serialNumber, issuer);
            checkCertificateValidityPeriod(certificatePair.getCertificate());
            checkCertificateIssuer(certificatePair.getCertificate());

            final PrivateKey privateKey = (PrivateKey) keystore.getKey(
                    certificatePair.getAlias(), getProperties().getProperty("keyPassword").toCharArray());

            LOG.debug("Recover BasicX509Credential.");
            final BasicX509Credential credential = new BasicX509Credential();

            LOG.debug("Load certificate");
            credential.setEntityCertificate(certificatePair.getCertificate());

            LOG.debug("Load privateKey");
            credential.setPrivateKey(privateKey);
            return credential;
        } catch (NoSuchAlgorithmException e) {
            LOG.info("ERROR : A 'xmldsig#rsa-sha1' cryptographic algorithm is requested but is not available in the environment.");
            throw new SAMLEngineException(e);
        } catch (KeyStoreException e) {
            LOG.warn("ERROR : Generic KeyStore exception.");
            throw new SAMLEngineException(e);
        } catch (UnrecoverableKeyException e) {
            LOG.warn("ERROR : UnrecoverableKey exception.");
            throw new SAMLEngineException(e);
        }
    }

    public Credential getPublicSigningCredential(KeyStore keystore) throws SAMLEngineException{
        try {
            final String serialNumber = getProperties().getProperty("serialNumber");
            final String issuer = getProperties().getProperty("issuer");

            CertificateAliasPair certificatePair = SAMLEngineUtils.getCertificatePair(keystore, serialNumber, issuer);
            // Create basic credential and set the EntityCertificate
            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(certificatePair.getCertificate());
            return credential;
        } catch (KeyStoreException e) {
            LOG.warn("ERROR : Generic KeyStore exception.");
            throw new SAMLEngineException(e);
        }
    }

    public Signature computeSignature(KeyStore keystore) throws SAMLEngineException{
        Signature signature = null;
        try {
            LOG.debug("Begin signature with openSaml");
            signature = (Signature) Configuration
                    .getBuilderFactory().getBuilder(
                            Signature.DEFAULT_ELEMENT_NAME).buildObject(
                            Signature.DEFAULT_ELEMENT_NAME);
            Credential credential=getSigningCredential(keystore);
            signature.setSigningCredential(credential);

            signature.setSignatureAlgorithm(getSignatureAlgorithmForSign());


            final SecurityConfiguration secConfiguration = SAMLEngineUtils.getStorkGlobalSecurityConfiguration();
            final NamedKeyInfoGeneratorManager keyInfoManager = secConfiguration
                    .getKeyInfoGeneratorManager();
            final KeyInfoGeneratorManager keyInfoGenManager = keyInfoManager
                    .getDefaultManager();
            final KeyInfoGeneratorFactory keyInfoGenFac = keyInfoGenManager
                    .getFactory(credential);
            final KeyInfoGenerator keyInfoGenerator = keyInfoGenFac
                    .newInstance();

            KeyInfo keyInfo = keyInfoGenerator.generate(credential);

            signature.setKeyInfo(keyInfo);
            signature.setCanonicalizationAlgorithm(
                    SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        } catch (org.opensaml.xml.security.SecurityException e) {
            LOG.warn("ERROR : Security exception.", e.getMessage());
            LOG.debug("ERROR : Security exception.", e);
            throw new SAMLEngineException(e);
        }
        return signature;
    }
}
