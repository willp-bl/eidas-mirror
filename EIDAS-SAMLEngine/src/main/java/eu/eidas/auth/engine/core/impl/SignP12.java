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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.InvalidPropertiesFormatException;
import java.util.List;
import java.util.Properties;

import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.engine.exceptions.SAMLEngineException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEvaluator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class SignP12. Class responsible for signing and validating of messages
 * SAML with a certificate store software.
 * 
 * @author fjquevedo
 */
public final class SignP12 extends AbstractSigner {

    /** The logger. */
    private static final Logger LOG = LoggerFactory.getLogger(SignP12.class
	    .getName());

    
    /** The p12 store. */
    private KeyStore p12Store = null;
    
    
    /** The trust store. */
    private KeyStore trustStore = null;
    

    /**
     * Gets the trust store.
     * 
     * @return the trust store
     */
    public KeyStore getTrustStore() {
        return trustStore;
    }

    /**
     * Sets the trust store.
     * 
     * @param newTrustStore the new trust store
     */
    public void setTrustStore(final KeyStore newTrustStore) {
        this.trustStore = newTrustStore;
    }


    /**
     * Gets the p12 store.
     * 
     * @return the p12 store
     */
    public KeyStore getP12Store() {
        return p12Store;
    }



    /**
     * Sets the p12 store.
     * 
     * @param newP12Store the new p12 store
     */
    public void setP12Store(final KeyStore newP12Store) {
        this.p12Store = newP12Store;
    }


    private InputStream loadFileProperties(String fileConf) throws IOException{
        InputStream fileProperties = null;
        try {
            LOG.trace("File to load " + fileConf);
            fileProperties = new FileInputStream(fileConf);
            getProperties().loadFromXML(fileProperties);
        } catch (Exception e) {
            LOG.info("Unable to load external file, trying in classpath");
            fileProperties = SignP12.class.getResourceAsStream("/" + fileConf);
            if (fileProperties == null) {
                fileProperties = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileConf);
                if (fileProperties == null) {
                    Enumeration<URL> files = ClassLoader.getSystemClassLoader().getResources(fileConf);
                    if (files != null && files.hasMoreElements()) {
                        LOG.debug("file loaded");
                        fileProperties = ClassLoader.getSystemClassLoader().getResourceAsStream(files.nextElement().getFile());
                    } else {
                        throw new IOException("ERROR : File not found" + fileConf, e);
                    }
                }
            }
        }
        return fileProperties;
    }

    /**
     * Initialize the file configuration.
     * 
     * @param fileConf name of the file configuration
     * 
     * @throws SAMLEngineException error at the load from  file configuration
     */
    public void init(final String fileConf) throws SAMLEngineException {
    	InputStream fileProperties = null;
    	setProperties(new Properties());
    	try {
                fileProperties=loadFileProperties(fileConf);
    			LOG.trace("Loaded " + fileProperties.available() + " bytes");
                getProperties().loadFromXML(fileProperties);

    	} catch (InvalidPropertiesFormatException e) {
    	    LOG.info("Exception: invalid properties format.", e);
    	    throw new SAMLEngineException(e);
    	} catch (IOException e) {
    	    LOG.info("Exception: invalid file: " + fileConf, e);
    	    throw new SAMLEngineException(e);
    	} finally {
    	    IOUtils.closeQuietly(fileProperties);
    	}
    }

    /**
     * Gets the certificate.
     * 
     * @return the X509Certificate
     *     
     */
    public X509Certificate getCertificate() {
	throw new NotImplementedException();
    }

    /**
     * Sign the token SAML.
     * 
     * @param tokenSaml token SAML
     * 
     * @return the X509Certificate signed.
     * 
     * @throws SAMLEngineException error at sign SAML token
     *
     */
    public SAMLObject sign(final SignableSAMLObject tokenSaml)
	    throws SAMLEngineException {
	LOG.info("Start Sign process");
	try {
		Signature signature = computeSignature(p12Store);


		tokenSaml.setSignature(signature);

	    LOG.info("Marshall samlToken.");
	    Configuration.getMarshallerFactory().getMarshaller(tokenSaml)
		    .marshall(tokenSaml);

	    LOG.info("Sign samlToken.");
	    Signer.signObject(signature);

	} catch (MarshallingException e) {
	    LOG.error("MarshallingException");
	    throw new SAMLEngineException(e);
	} catch (SignatureException e) {
	    LOG.error("Signature exception.");
	    throw new SAMLEngineException(e);
	}

	return tokenSaml;
    }

    private void validateProfileSignature(final SignableSAMLObject tokenSaml)throws SAMLEngineException{
        final SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
        try {
            // Indicates signature id conform to SAML Signature profile
            sigProfValidator.validate(tokenSaml.getSignature());
        } catch (ValidationException e) {
            LOG.info("ValidationException: signature isn't conform to SAML Signature profile.");
            throw new SAMLEngineException(e);
        }

    }
    /**
     * Validate signature.
     * 
     * @param tokenSaml token SAML
     * 
     * @return the SAMLObject validated.
     * 
     * @throws SAMLEngineException error validate signature
     * 
     */
    public SAMLObject validateSignature(final SignableSAMLObject tokenSaml, String messageFormat)
	    throws SAMLEngineException {
	LOG.info("Start signature validation.");
	try {

	    // Validate structure signature
        validateProfileSignature(tokenSaml);

	    String aliasCert = null;
	    X509Certificate certificate;

	    final List<Credential> trustCred = new ArrayList<Credential>();

	    for (final Enumeration<String> e = trustStore.aliases(); e
		    .hasMoreElements();) {
		aliasCert = e.nextElement();
		final BasicX509Credential credential = new BasicX509Credential();
		certificate = (X509Certificate) trustStore
			.getCertificate(aliasCert);
		credential.setEntityCertificate(certificate);
		trustCred.add(credential);
	    }

	    final KeyInfo keyInfo = tokenSaml.getSignature().getKeyInfo();

	    final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo
		    .getX509Datas().get(0).getX509Certificates().get(0);

	    final CertificateFactory certFact = CertificateFactory
		    .getInstance("X.509");
	    final ByteArrayInputStream bis = new ByteArrayInputStream(Base64
		    .decode(xmlCert.getValue()));
	    final X509Certificate cert = (X509Certificate) certFact
		    .generateCertificate(bis);

	    // Exist only one certificate
	    final BasicX509Credential entityX509Cred = new BasicX509Credential();
	    entityX509Cred.setEntityCertificate(cert);

	    // Validate trust certificates
	    final ExplicitKeyTrustEvaluator keyTrustEvaluator = 
		new ExplicitKeyTrustEvaluator();
	    if (!keyTrustEvaluator.validate(entityX509Cred, trustCred)) {
		    throw new SAMLEngineException("Certificate it is not trusted.");
	    }

	    // Validate signature
	    final SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
        LOG.info("Key algorithm {}", SecurityHelper.getKeyAlgorithmFromURI(tokenSaml.getSignature().getSignatureAlgorithm()));
	    sigValidator.validate(tokenSaml.getSignature());

	} catch (ValidationException e) {
	    LOG.info("ValidationException.");
	    throw new SAMLEngineException(e);
	} catch (KeyStoreException e) {
	    LOG.error("KeyStoreException.", e);
	    throw new SAMLEngineException(e);
	} catch (GeneralSecurityException e) {
	    LOG.error("GeneralSecurityException.", e);
	    throw new SAMLEngineException(e);
	}
	return tokenSaml;
    }


    /**
     * Load cryptographic service provider.
     * 
     * @throws SAMLEngineException the SAML engine exception
     */
    public void loadCryptServiceProvider() throws SAMLEngineException {
	LOG.info("Load Cryptographic Service Provider");
	
	FileInputStream fis = null;
	FileInputStream fisTrustStore = null;
	
	try {
	    // Dynamically register Bouncy Castle provider.
	    boolean found = false;
	    // Check if BouncyCastle is already registered as a provider
	    final Provider[] providers = Security.getProviders();
	    for (int i = 0; i < providers.length; i++) {
		if (providers[i].getName().equals(
			BouncyCastleProvider.PROVIDER_NAME)) {
		    found = true;
		}
	    }

	    // Register only if the provider has not been previously registered
	    if (!found) {
		LOG.debug("SAMLCore: Register Bouncy Castle provider.");
		Security.insertProviderAt(new BouncyCastleProvider(), Security
			.getProviders().length);
	    }

	    p12Store = KeyStore.getInstance(getProperties().getProperty("keystoreType"));

	    fis = new FileInputStream(getProperties().getProperty("keystorePath"));

	    p12Store.load(fis, getProperties().getProperty("keyStorePassword").toCharArray());
	    
	    
	    trustStore = KeyStore.getInstance(getProperties().getProperty("trustStoreType"));
	    
	    fisTrustStore = new FileInputStream(getProperties().getProperty("trustStorePath"));
	    trustStore.load(fisTrustStore, getProperties().getProperty(
				"trustStorePassword").toCharArray());

	} catch (Exception e) {
	    throw new SAMLEngineException(
		    "Error loading CryptographicServiceProvider", e);
	}  finally {
	    IOUtils.closeQuietly(fis);
	    IOUtils.closeQuietly(fisTrustStore);
	}	
    }
	public void setMetadataProcessor(MetadataProcessorI processor){
		//TODO
	}
	public SAMLObject signMetadata(SignableSAMLObject tokenSaml) throws SAMLEngineException{
		return sign(tokenSaml);
	}


}
