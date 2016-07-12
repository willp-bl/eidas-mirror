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

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.InvalidPropertiesFormatException;
import java.util.List;
import java.util.Properties;

import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEvaluator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import eu.stork.peps.exceptions.SAMLEngineException;

/**
 * The Class HWSign. Module of sign.
 * 
 * @author fjquevedo
 */
public final class SignHW extends AbstractSigner {

    /** The Constant CONFIGURATION_FILE. */
    private static final String CONF_FILE = "configurationFile";

    /** The Constant KEYSTORE_TYPE.
    private static final String KEYSTORE_TYPE = "keystoreType" */

    /** The logger. */
    private static final Logger LOG = LoggerFactory.getLogger(SignHW.class
	    .getName());

    /** The stork own key store. */
    private KeyStore storkOwnKeyStore = null;

    /**
     * Gets the stork own key store.
     * 
     * @return the stork own key store
     */
    public KeyStore getStorkOwnKeyStore() {
	return storkOwnKeyStore;
    }
    
    /**
     * Gets the stork trustStore.
     * 
     * @return the stork own key store
     */
    public KeyStore getTrustStore() {
	return storkOwnKeyStore;
    }

    /**
     * Sets the stork own key store.
     * 
     * @param newkOwnKeyStore the new stork own key store
     */
    public void setStorkOwnKeyStore(final KeyStore newkOwnKeyStore) {
	this.storkOwnKeyStore = newkOwnKeyStore;
    }

    /**
     * @see
     * eu.stork.peps.auth.engine.core.SAMLEngineSignI#init(java.lang.String)
     * @param fileConf file of configuration
     * @throws SAMLEngineException error in read file
     */
    public void init(final String fileConf)
	    throws SAMLEngineException {
	InputStream inputStr = null;
	try {
	inputStr = SignHW.class.getResourceAsStream("/"
		+ fileConf);
        setProperties( new Properties());

        getProperties().loadFromXML(inputStr);
	} catch (final InvalidPropertiesFormatException e) {
	    LOG.info("ERROR : Exception: invalid properties format.");
	    throw new SAMLEngineException(e);
	} catch (IOException e) {
	    LOG.info("ERROR : Exception: invalid file: " + fileConf);
	    throw new SAMLEngineException(e);
	} finally {
	    IOUtils.closeQuietly(inputStr);
	}
    }


    /**
     * @see eu.stork.peps.auth.engine.core.SAMLEngineSignI#getCertificate()
     * @return the X509Certificate.
     */
    public X509Certificate getCertificate() {
	throw new NotImplementedException();
    }

    /**
     * @see
     * eu.stork.peps.auth.engine.core.SAMLEngineSignI#sign(SignableSAMLObject tokenSaml)
     * @param tokenSaml signable SAML Object
     * @return the SAMLObject signed.
     * @throws SAMLEngineException error in sign token saml
     */
    public SAMLObject sign(final SignableSAMLObject tokenSaml) throws SAMLEngineException {

	try {
	    LOG.debug("Start procces of sign");
	    final char[] pin = getProperties().getProperty("keyPassword")
		    .toCharArray();

	    storkOwnKeyStore.load(null, pin);

		Signature signature = computeSignature(storkOwnKeyStore);
	    tokenSaml.setSignature(signature);

	    LOG.debug("Marshall samlToken.");
	    org.opensaml.xml.Configuration.getMarshallerFactory()
		    .getMarshaller(tokenSaml).marshall(tokenSaml);

	    LOG.debug("Sign samlToken.");
	    Signer.signObject(signature);

	} catch (final MarshallingException e) {
	    LOG.info("ERROR : MarshallingException", e.getMessage());
	    throw new SAMLEngineException(e);
	} catch (final NoSuchAlgorithmException e) {
		LOG.info("ERROR : A 'xmldsig#rsa-sha1' cryptographic algorithm is requested but is not available in the environment.", e.getMessage());
	    throw new SAMLEngineException(e);
	} catch (final SignatureException e) {
		LOG.info("ERROR : Signature exception.", e.getMessage());
	    throw new SAMLEngineException(e);
	} catch (final CertificateException e) {
		LOG.info("ERROR : Certificate exception.", e.getMessage());
	    throw new SAMLEngineException(e);
	} catch (final IOException e) {
		LOG.info("ERROR : IO exception.", e.getMessage());
	    throw new SAMLEngineException(e);
	}

	return tokenSaml;
    }

    /**
     * @see
     * eu.stork.peps.auth.engine.core.SAMLEngineSignI#validateSignature(SignableSAMLObject)
     * @param tokenSaml the token saml
     * @return the SAMLObject validated.
     * @throws SAMLEngineException exception in validate signature
     */
    public SAMLObject validateSignature(final SignableSAMLObject tokenSaml)
	    throws SAMLEngineException {
	LOG.info("Start signature validation.");
	try {

	    // Validate structure signature
	    final SAMLSignatureProfileValidator signProfValidator = 
		new SAMLSignatureProfileValidator();

	    // Indicates signature id conform to SAML Signature profile
	    signProfValidator.validate(tokenSaml.getSignature());

	    String aliasCert;
	    X509Certificate certificate;

	    final List<Credential> trustedCred = new ArrayList<Credential>();

	    for (final Enumeration<String> e = storkOwnKeyStore.aliases(); e
		    .hasMoreElements();) {
		aliasCert = e.nextElement();
		final BasicX509Credential credential = new BasicX509Credential();
		certificate = (X509Certificate) storkOwnKeyStore
			.getCertificate(aliasCert);
		credential.setEntityCertificate(certificate);
		trustedCred.add(credential);
	    }

	    final KeyInfo keyInfo = tokenSaml.getSignature().getKeyInfo();
	    final List<X509Certificate> listCertificates = KeyInfoHelper
		    .getCertificates(keyInfo);

	    if (listCertificates.size() != 1) {
		throw new SAMLEngineException("Only must be one certificate");
	    }

	    // Exist only one certificate
	    final BasicX509Credential entityX509Cred = new BasicX509Credential();
	    entityX509Cred.setEntityCertificate(listCertificates.get(0));

	    final ExplicitKeyTrustEvaluator keyTrustEvaluator = 
		new ExplicitKeyTrustEvaluator();
	    if (!keyTrustEvaluator.validate(entityX509Cred, trustedCred)) {
		throw new SAMLEngineException("Certificate it is not trusted.");
	    }

	    final SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
        LOG.info("Key algorithm-lenght {}", SecurityHelper.getKeyAlgorithmFromURI(tokenSaml.getSignature().getSignatureAlgorithm()));
	    sigValidator.validate(tokenSaml.getSignature());

	} catch (final ValidationException e) {
	    LOG.info("ValidationException.", e);
	    throw new SAMLEngineException(e);
	} catch (final KeyStoreException e) {
	    LOG.error("ValidationException.", e);
	    throw new SAMLEngineException(e);
	} catch (final CertificateException e) {
	    LOG.error("CertificateException.", e);
	    throw new SAMLEngineException(e);
	}
	return tokenSaml;
    }

    /**
     * load cryptographic service provider.
     * 
     * @throws SAMLEngineException the SAML engine exception
     * Note this class was using pkcs11Provider
     * final Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(inputStream)
     * if (Security.getProperty(pkcs11Provider.getName()) == null) {
     * Security.insertProviderAt(pkcs11Provider, Security .getProviders().length)
     * }
     * storkOwnKeyStore = KeyStore.getInstance(properties.getProperty(KEYSTORE_TYPE))
     */
    public void loadCryptServiceProvider() throws SAMLEngineException {
	LOG.info("Load Cryptographic Service Provider");
	InputStream inputStream = null; 
	 
	try {
	    inputStream = SignHW.class.getResourceAsStream("/"
		    + getProperties().getProperty(CONF_FILE));

	} catch (final Exception e) {	       
	    throw new SAMLEngineException(
		    "Error loading CryptographicServiceProvider", e);
	} finally {
	    IOUtils.closeQuietly(inputStream);
	}
    }
	public void setMetadataProcessor(MetadataProcessorI processor){
		//TODO
	}


}
