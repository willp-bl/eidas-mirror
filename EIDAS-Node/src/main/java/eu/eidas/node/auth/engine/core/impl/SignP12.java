package eu.eidas.node.auth.engine.core.impl;

import java.io.*;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.InvalidPropertiesFormatException;
import java.util.List;
import java.util.Properties;

import eu.eidas.auth.engine.X500PrincipalUtil;
import eu.eidas.auth.engine.core.impl.AbstractSigner;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.engine.exceptions.SAMLEngineException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEvaluator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SignP12 extends AbstractSigner {

    private static final int CERTIFICATE_SERIAL_NB_RADIX = 16;
    private static final Logger LOG = LoggerFactory.getLogger(eu.eidas.auth.engine.core.impl.SignP12.class);
    private KeyStore p12Store;
    private KeyStore trustStore;

    public SignP12() {
        p12Store = null;
        trustStore = null;
        setProperties(null);
    }

    public KeyStore getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(KeyStore newTrustStore) {
        trustStore = newTrustStore;
    }

    public KeyStore getP12Store() {
        return p12Store;
    }

    public void setP12Store(KeyStore newP12Store) {
        p12Store = newP12Store;
    }

    public void init(final String fileConf) throws SAMLEngineException {
        try {
            if (!loadPropertiesFileAsExternalResource(fileConf)){
                loadPropertiesFileAsInternalResource(fileConf);
            }
        } catch (IOException e) {
            LOG.info("BUSINESS EXCEPTION : invalid file: " + fileConf);
            throw new SAMLEngineException(e);
        }
    }

    private boolean loadPropertiesFileAsExternalResource(final String fileConf) {
        LOG.trace("File to upload " + fileConf);
        InputStream fileProperties = null;
        boolean loaded = false;
        try {
            fileProperties = new FileInputStream(fileConf);
            Properties properties=new Properties();
            properties.loadFromXML(fileProperties);
            setProperties(properties);
            loaded = true;
        } catch (IOException e) {
            LOG.info("BUSINESS EXCEPTION : Failed to load the external resource. Retrying as internal file.", e.getMessage());
            LOG.debug("BUSINESS EXCEPTION : Failed to load the external resource. Retrying as internal file.", e);
        } finally {
            IOUtils.closeQuietly(fileProperties);
        }
        return loaded;
    }

    private void loadPropertiesFileAsInternalResource(final String fileConf) throws IOException {
        InputStream fileProperties = null;
        try {
            fileProperties = SignP12.class.getResourceAsStream("/" + fileConf);
            if (fileProperties == null) {
                fileProperties = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileConf);
                if (fileProperties == null) {
                    Enumeration<URL> files = ClassLoader.getSystemClassLoader().getResources(fileConf);
                    if (files != null && files.hasMoreElements()) {
                        LOG.debug("File(s) found. Taking the first");
                        fileProperties = ClassLoader.getSystemClassLoader().getResourceAsStream(files.nextElement().getFile());
                    } else {
                        throw new IOException("Unable to load the file: " + fileConf);
                    }
                }
            }
            LOG.trace("Loading " + fileProperties.available() + " bytes");
            getProperties().loadFromXML(fileProperties);
        } catch (InvalidPropertiesFormatException e) {
            LOG.debug("Exception: invalid properties format.");
            throw e;
        } finally {
            IOUtils.closeQuietly(fileProperties);
        }
    }

    public X509Certificate getCertificate() {
        throw new NotImplementedException();
    }

    private Signature getSignatureWithOpenSAML(BasicX509Credential credential) throws SecurityException{
        LOG.trace("Begin signature with openSaml");
        Signature signature = (Signature)Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        SecurityConfiguration secConfiguration = Configuration.getGlobalSecurityConfiguration();
        NamedKeyInfoGeneratorManager keyInfoManager = secConfiguration.getKeyInfoGeneratorManager();
        KeyInfoGeneratorManager keyInfoGenManager = keyInfoManager.getDefaultManager();
        KeyInfoGeneratorFactory keyInfoGenFac = keyInfoGenManager.getFactory(credential);
        KeyInfoGenerator keyInfoGenerator = keyInfoGenFac.newInstance();
        KeyInfo keyInfo = keyInfoGenerator.generate(credential);
        signature.setKeyInfo(keyInfo);
        signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
        return signature;
    }

    public Signature computeSignature(KeyStore keystore) throws SAMLEngineException{
        try {
            return getSignatureWithOpenSAML(getCredential());
        }catch(SecurityException se){
            LOG.info("SecurityException while computing the signature:", se.getMessage());
            LOG.debug("SecurityException while computing the signature:", se);
        }
        return null;
    }

    private String getAlias() throws SAMLEngineException{
        X509Certificate certificate;
        boolean find = false;
        String serialNumber = getProperties().getProperty("serialNumber");
        String issuer = getProperties().getProperty("issuer");
        String alias = null;
        try {
            Enumeration e = p12Store.aliases();
            do {
                if(!e.hasMoreElements() || find){
                    break;
                }
                String aliasCert = (String)e.nextElement();
                certificate = (X509Certificate)p12Store.getCertificate(aliasCert);
                String serialNum = certificate.getSerialNumber().toString(CERTIFICATE_SERIAL_NB_RADIX);
                X500Name issuerDN = new X500Name(certificate.getIssuerDN().getName());
                X500Name issuerDNConf = new X500Name(issuer);
                if(serialNum.equalsIgnoreCase(serialNumber)
                        && X500PrincipalUtil.principalEquals(issuerDN, issuerDNConf)){
                    alias = aliasCert;
                    find = true;
                }
            } while(true);
        } catch (KeyStoreException e1) {
            LOG.error("Generic KeyStore exception.");
            throw new SAMLEngineException(e1);
        }
        return alias;
    }
    private BasicX509Credential getCredential() throws SAMLEngineException{
        X509Certificate certificate;
        BasicX509Credential credential = null;
        try {
            String alias = getAlias();
            certificate = (X509Certificate)p12Store.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey)p12Store.getKey(alias, getProperties().getProperty("keyPassword").toCharArray());
            LOG.info("Recover BasicX509Credential.");
            credential = new BasicX509Credential();
            LOG.debug("Load certificate");
            credential.setEntityCertificate(certificate);
            LOG.debug("Load privateKey");
            credential.setPrivateKey(privateKey);
        } catch (KeyStoreException e1) {
            LOG.error("Generic KeyStore exception.");
            throw new SAMLEngineException(e1);
        } catch (UnrecoverableKeyException e){
            LOG.error("UnrecoverableKey exception.");
            throw new SAMLEngineException(e);
        } catch (NoSuchAlgorithmException e){
            LOG.error("A 'xmldsig#rsa-sha1' cryptographic algorithm is requested but is not available in the environment.");
            throw new SAMLEngineException(e);
        }
        return credential;
    }

    public SAMLObject sign(SignableSAMLObject tokenSaml) throws SAMLEngineException {
        LOG.info("Start Sign process");
        try {
            BasicX509Credential credential = getCredential();
            Signature signature = getSignatureWithOpenSAML(credential);
            tokenSaml.setSignature(signature);
            LOG.info("Marshall samlToken.");
            Configuration.getMarshallerFactory().getMarshaller(tokenSaml).marshall(tokenSaml);
            LOG.info("Sign samlToken.");
            Signer.signObject(signature);
        } catch(MarshallingException e) {
            LOG.error("MarshallingException");
            throw new SAMLEngineException(e);
        } catch(SignatureException e) {
            LOG.error("Signature exception.");
            throw new SAMLEngineException(e);
        } catch(SecurityException e) {
            LOG.error("Security exception.");
            throw new SAMLEngineException(e);
        }
        return tokenSaml;
    }

    public SAMLObject validateSignature(SignableSAMLObject tokenSaml, String messageFormat) throws SAMLEngineException {
        LOG.info("Start signature validation.");
        try {
            SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
            sigProfValidator.validate(tokenSaml.getSignature());
            LOG.info("tokenSaml validated: signature is conform to SAML Signature profile.");
            String aliasCert = null;
            List trustCred = new ArrayList();
            BasicX509Credential credential;
            for(Enumeration e = trustStore.aliases(); e.hasMoreElements(); trustCred.add(credential)) {
                aliasCert = (String)e.nextElement();
                credential = new BasicX509Credential();
                X509Certificate certificate = (X509Certificate)trustStore.getCertificate(aliasCert);
                credential.setEntityCertificate(certificate);
            }

            KeyInfo keyInfo = tokenSaml.getSignature().getKeyInfo();
            org.opensaml.xml.signature.X509Certificate xmlCert = (org.opensaml.xml.signature.X509Certificate)((X509Data)keyInfo.getX509Datas().get(0)).getX509Certificates().get(0);
            CertificateFactory certFact = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
            X509Certificate cert = (X509Certificate)certFact.generateCertificate(bis);
            BasicX509Credential entityX509Cred = new BasicX509Credential();
            entityX509Cred.setEntityCertificate(cert);
            ExplicitKeyTrustEvaluator keyTrustEvaluator = new ExplicitKeyTrustEvaluator();
            if(!keyTrustEvaluator.validate(entityX509Cred, trustCred)){
                throw new SAMLEngineException("Certificate it is not trusted.");
            }
            SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
            sigValidator.validate(tokenSaml.getSignature());
            LOG.info("tokenSaml validated (2): signature is conform to SAML Signature profile.");
        } catch(ValidationException e) {
            LOG.error("ValidationException.");
            throw new SAMLEngineException(e);
        } catch(KeyStoreException e) {
            LOG.error("KeyStoreException.", e);
            throw new SAMLEngineException(e);
        } catch(GeneralSecurityException e) {
            LOG.error("GeneralSecurityException.", e);
            throw new SAMLEngineException(e);
        }
        return tokenSaml;
    }

    public void loadCryptServiceProvider() throws SAMLEngineException {
        FileInputStream fis;
        FileInputStream fisTrustStore;
        LOG.info("Load Cryptographic Service Provider");
        fis = null;
        fisTrustStore = null;
        try {
            boolean found = false;
            Provider providers[] = Security.getProviders();
            for(int i = 0; i < providers.length; i++){
                if(providers[i].getName().equals(BouncyCastleProvider.PROVIDER_NAME)) {
                    found = true;
                }
            }
            if (!found) {
                LOG.debug("SAMLCore: Register Bouncy Castle provider.");
                Security.insertProviderAt(new BouncyCastleProvider(), Security.getProviders().length);
            }
            p12Store = KeyStore.getInstance(getProperties().getProperty("keystoreType"));
            fis = new FileInputStream(getProperties().getProperty("keystorePath"));
            p12Store.load(fis, getProperties().getProperty("keyStorePassword").toCharArray());
            trustStore = KeyStore.getInstance(getProperties().getProperty("trustStoreType"));
            fisTrustStore = new FileInputStream(getProperties().getProperty("trustStorePath"));
            trustStore.load(fisTrustStore, getProperties().getProperty("trustStorePassword").toCharArray());
        } catch(Exception e) {
            throw new SAMLEngineException("BUSINESS EXCEPTION when loading CryptographicServiceProvider", e);
        }  finally {
    	    IOUtils.closeQuietly(fis);
    	    IOUtils.closeQuietly(fisTrustStore);
    	}
    }
    public void setMetadataProcessor(MetadataProcessorI processor){
        //TODO
    }
    public SAMLObject signMetadata(SignableSAMLObject tokenSaml) throws SAMLEngineException{
        //TODO
        return sign(tokenSaml);
    }

}
