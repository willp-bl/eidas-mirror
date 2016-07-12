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

import eu.stork.encryption.SAMLAuthnResponseDecrypter;
import eu.stork.encryption.SAMLAuthnResponseEncrypter;
import eu.stork.encryption.exception.DecryptionException;
import eu.stork.encryption.exception.EncryptionException;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PropertiesLoader;
import eu.stork.peps.auth.engine.SAMLEngineUtils;
import eu.stork.peps.auth.engine.X500PrincipalUtil;
import eu.stork.peps.auth.engine.core.SAMLEngineEncryptionI;
import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.samlengineconfig.BinaryParameter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Created by bodabel on 10/12/2014.
 */
public class EncryptionSW extends AbstractSAMLEngineModule implements SAMLEngineEncryptionI {

    /**
     * The logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(EncryptionSW.class
            .getName());

    /**
     * The Constant RESPONSE_TO_POINT_ISSUER.
     */
    private static final String RESPONSE_TO_POINT_ISSUER = "responseToPointIssuer";

    /**
     * The Constant RESPONSE_FROM_POINT_ISSUER.
     */
    private static final String RESPONSE_FROM_POINT_ISSUER = "responseDecryptionIssuer";
    /**
     * The Constant SERIAL_NUMBER.
     */
    private static final String SERIAL_NUMBER = "serialNumber";

    /**
     * The Constant KEYSTORE_TYPE.
     */
    private static final String KEYSTORE_TYPE = "keystoreType";

    /**
     * The Constant KEY_STORE_PASSWORD.
     */
    private static final String KEY_STORE_PASS = "keyStorePassword";
    public static final String RESPONSE_TO_POINT_SERIAL_NUMBER = "responseToPointSerialNumber";
    public static final String ENCRYPTION_ACTIVATION = "encryptionActivation";
    public static final String KEYSTORE_PATH = "keystorePath";
    private static final  String KEY_PASSWORD="keyPassword";
    /**
     * name of the parameter storing the JCA provider name
     */
    private static final String PROVIDER_NAME="jcaProviderName";
    private static final String DEFAULT_PROVIDER_NAME_VALUE=BouncyCastleProvider.PROVIDER_NAME;

    /**
     * The encryption key store.
     */
    private KeyStore encryptionKeyStore = null;

    /**
     * The SW encryption properties
     */

    private SAMLAuthnResponseEncrypter samlAuthnResponseEncrypter;

    private SAMLAuthnResponseDecrypter samlAuthnResponseDecrypter;

    /**
     * allows to force a provider for the encryptiorn
     */
    private String jcaProviderName=null;
    MetadataProcessorI metadataProcessor = null;
    public void setMetadataProcessor(MetadataProcessorI processor) {
        metadataProcessor = processor;
    }



    /**
     * Encryption configurations for the engine.
     * Specify to use encryption/decryption for the instances
     */
    private Properties encryptionActivationProperties;

    @Override
    public void init(String fileConf) throws SAMLEngineException {
        //ENCRYPTION CONFIGURATION
        //

        try {
            this.loadProperties(fileConf);
            this.init(properties);
        }catch(SAMLEngineException e){
            throw e;
        }catch (Exception e) {
            LOG.error("Error init method");
            throw new SAMLEngineException(e);
        }
    }
    @Override
    public void init(Properties propsConf) throws SAMLEngineException {
        try {
            properties = propsConf;
            this.loadCryptServiceProvider();
            this.loadKeystore();
            this.initActivationConf(properties);


            //If algorithms should be parametrized from config it comes here somewhere provided for constructors...
            samlAuthnResponseEncrypter = new SAMLAuthnResponseEncrypter();
            samlAuthnResponseDecrypter = new SAMLAuthnResponseDecrypter();
            if(properties.containsKey(PROVIDER_NAME)){
                setJcaProviderName(properties.getProperty(PROVIDER_NAME));
            }else{
                setJcaProviderName(DEFAULT_PROVIDER_NAME_VALUE);
            }
            if(getJcaProviderName()!=null){
                samlAuthnResponseEncrypter.setJcaProviderName(getJcaProviderName());
                samlAuthnResponseDecrypter.setJcaProviderName(getJcaProviderName());
            }
            LOG.debug("Encryption loaded.");
        } catch (Exception e) {
            LOG.error("Error init method");
            throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(), PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage(), e);
        }

    }

    private void initActivationConf(Properties props) throws SAMLEngineException {
        InputStream is=null;
        try {
            Object obj=props.get(ENCRYPTION_ACTIVATION);
            if(obj instanceof String) {
                String fileConf=(String)obj;
                LOG.debug("File containing encryption configuration: " + fileConf);
                encryptionActivationProperties = PropertiesLoader.loadPropertiesXMLFile(fileConf);
            }else if (obj instanceof BinaryParameter){
                encryptionActivationProperties=new Properties();
                is=new ByteArrayInputStream((byte[])((BinaryParameter)obj).getValue());
                encryptionActivationProperties.loadFromXML(is);
            }
        }catch(FileNotFoundException fe){
            LOG.error("ERROR : File not found! Encryption will not be activated {}", fe);
        }catch(Exception e){
            LOG.error("ERROR : loading encryption activation configuration");
            throw new SAMLEngineException(e);
        }finally{
            IOUtils.closeQuietly(is);
        }
    }

    @Override
    public Response encryptSAMLResponse(Response authResponse, String destinationCountryCode, String requestIssuer) throws SAMLEngineException {
        BasicX509Credential credential=(BasicX509Credential)getMetadataEncryptionCredential(requestIssuer);
        if(credential==null && isEncryptionEnable(destinationCountryCode)) {
            LOG.debug("Encryption enable, proceeding...");
            StringBuilder issuerKey = new StringBuilder(RESPONSE_TO_POINT_ISSUER).append(".").append(destinationCountryCode);
            StringBuilder serialNumberKey = new StringBuilder("responseToPointSerialNumber").append(".").append(destinationCountryCode);
            final String serialNumber = properties.getProperty(serialNumberKey.toString());
            final String responseToPointIssuer = properties.getProperty(issuerKey.toString());
            if (responseToPointIssuer != null && !responseToPointIssuer.isEmpty()) {
                try {
                    String aliasCert;
                    String alias = null;
                    X509Certificate responsePointAliasCert = null;
                    boolean find = false;

                    for (final Enumeration<String> e = encryptionKeyStore.aliases(); e.hasMoreElements() && !find; ) {
                        aliasCert = e.nextElement();
                        responsePointAliasCert = (X509Certificate) encryptionKeyStore.getCertificate(aliasCert);

                        final String serialNum = responsePointAliasCert.getSerialNumber().toString(16);

                        X500Name issuerDN = new X500Name(responsePointAliasCert.getIssuerDN().getName());
                        X500Name issuerDNConf = new X500Name(responseToPointIssuer);

                        if (serialNum.equalsIgnoreCase(serialNumber)
                                && X500PrincipalUtil.principalEquals(issuerDN, issuerDNConf)) {
                            alias = aliasCert;
                            find = true;
                        }
                    }
                    if (!find) {
                        throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_CERTIFICATE.errorCode(), PEPSErrors.SAML_ENGINE_INVALID_CERTIFICATE.errorMessage());
                    }
                    // Find configured certificate
                    responsePointAliasCert = (X509Certificate) encryptionKeyStore.getCertificate(alias);
                    checkCertificateValidityPeriod(responsePointAliasCert);
                    checkCertificateIssuer(responsePointAliasCert);
                    // Create basic credential and set the EntityCertificate
                    credential = new BasicX509Credential();
                    credential.setEntityCertificate(responsePointAliasCert);
                }catch(KeyStoreException kse) {
                    throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_KEYSTORE.errorCode(), PEPSErrors.SAML_ENGINE_INVALID_KEYSTORE.errorMessage(), kse);
                }catch (Exception e) {
                    LOG.warn("Error encrypting SAML Response.", e.getMessage());
                    throw new SAMLEngineException(e);
                } finally {
                    LOG.debug("Credential for encryption of SAML Response done for target: '" + responseToPointIssuer + "'");
                }
            } else {
                LOG.error("Encryption of SAML Response NOT done, because no " + RESPONSE_TO_POINT_ISSUER + " " +
                        "configured!");
            }
        }
        if(isEncryptionEnable(destinationCountryCode)){
            if(credential==null){
                throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_UNENCRYPTED_RESPONSE.errorCode(), PEPSErrors.SAML_ENGINE_UNENCRYPTED_RESPONSE.errorMessage());
            }
            try {
                // Execute encryption
                return samlAuthnResponseEncrypter.encryptSAMLResponse(authResponse, credential);
            } catch (EncryptionException e) {
                LOG.info("ERROR : Error encrypting SAML Response.", e.getMessage());
                throw new SAMLEngineException(e);
            } finally {
                LOG.debug("Encryption of SAML Response done for target: "+credential.getEntityCertificate().getIssuerDN());
            }

        }
        return authResponse;
    }

    @Override
    public Response decryptSAMLResponse(Response authResponse, String fromCountryCode) throws SAMLEngineException {
        if(isModuleEncryptionEnable()) {
            LOG.debug("Decryption enable, proceeding...");
            //Decryption is always made with private key. Only own certificate needed
            final String responseFromPointIssuer = properties.getProperty(RESPONSE_FROM_POINT_ISSUER);
            if (responseFromPointIssuer != null && !responseFromPointIssuer.isEmpty()) {
                try {
                    // Aquire Private Key of current point as a SAMLResponse target
                    // e.g.: the targeted C-PEPS aquires its own PrivateKey from its own KeyStore
                    // Aquire PublicKey of SAMLResponse Point
                    // e.g.: SAMLAdapter aquires PublicKey of the targeted C-PEPS from the SAMLAdapter's KeyStore

                    String aliasCert;
                    String alias = null;
                    X509Certificate responsePointAliasCert = null;
                    boolean find = false;

                    //KEYINFO CERTIFICATE
                    EncryptedAssertion encAssertion = authResponse.getEncryptedAssertions().get(0);
                    EncryptedKey encryptedSymmetricKey = encAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
                    org.opensaml.xml.signature.X509Certificate keyInfoX509Cert = encryptedSymmetricKey.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
                    final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(keyInfoX509Cert.getValue()));
                    final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
                    final X509Certificate keyInfoCert = (X509Certificate) certFact.generateCertificate(bis);

                    //RESPOINSE POINT CERTIFICATE FIND
                    for (final Enumeration<String> e = encryptionKeyStore.aliases(); e.hasMoreElements(); ) {
                        aliasCert = e.nextElement();
                        responsePointAliasCert = (X509Certificate) encryptionKeyStore.getCertificate(aliasCert);
                        //CHECK IF CERTIFICATES EQUAL
                        if (Arrays.equals(keyInfoCert.getTBSCertificate(), responsePointAliasCert.getTBSCertificate())) {
                            alias = aliasCert;
                            find = true;
                            break;
                        }
                    }
                    if (!find) {
                        throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_CERTIFICATE.errorCode(), PEPSErrors.SAML_ENGINE_INVALID_CERTIFICATE.errorMessage());
                    }
                    String responseAlgorithm = encAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm();
                    Set<String> allowedAlgorithms=getAllowedAlgorithms();
                    if(allowedAlgorithms==null || allowedAlgorithms.isEmpty() || !allowedAlgorithms.contains(responseAlgorithm)){
                        throw new SAMLEngineException(PEPSErrors.INVALID_ENCRYPTION_ALGORITHM.errorCode());
                    }
                    //GET PRIVATE KEY by found alias
                    final PrivateKey responsePointAliasPrivateKey = (PrivateKey) encryptionKeyStore.getKey(
                            alias, properties.getProperty(KEY_PASSWORD).toCharArray());

                    BasicX509Credential credential = new BasicX509Credential();
                    credential.setPrivateKey(responsePointAliasPrivateKey);

                    credential.setEntityCertificate(keyInfoCert);
                    //metadata check: encryption certificate is retrieved and used during the encryption phase
                    //decryption will fail if the public key credential exposed in the metadata (and used during encryption)
                    //is not paired with the private key

                    return samlAuthnResponseDecrypter.decryptSAMLResponse(authResponse, credential);
                }catch(KeyStoreException kse) {
                    throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_KEYSTORE.errorCode(), PEPSErrors.SAML_ENGINE_INVALID_KEYSTORE.errorMessage(), kse);
                }catch(SAMLEngineException e) {
                    throw e;
                }catch (UnrecoverableKeyException e) {
                    LOG.info("ERROR : Error decrypting SAML Response.", e.getMessage());
                    throw new SAMLEngineException(e);
                }catch (NoSuchAlgorithmException e) {
                    LOG.error("Error decrypting SAML Response.",e.getMessage());
                    throw new SAMLEngineException(e);
                }catch (CertificateException e) {
                    LOG.error("Error decrypting SAML Response.",e.getMessage());
                    throw new SAMLEngineException(e);
                }catch (DecryptionException e) {
                    LOG.error("Error decrypting SAML Response.",e.getMessage());
                    throw new SAMLEngineException(e);
                }finally {
                    LOG.debug("Decryption of SAML Response done on: '" + responseFromPointIssuer + "'");
                }
            } else {
                LOG.info("ERROR : Decryption of SAML Response NOT done, because no " + RESPONSE_FROM_POINT_ISSUER + " " +
                        "configured!");
            }
        }
        return authResponse;
    }

    private final void loadProperties(String fileConf) throws SAMLEngineException {
        LOG.debug("Loading Encryption Properties");
        InputStream fileProperties = null;
        try {
            fileProperties = SignSW.class.getResourceAsStream("/" + fileConf);
            properties = new Properties();
            properties.loadFromXML(fileProperties);
            fileProperties.close();
        } catch (InvalidPropertiesFormatException e) {
            LOG.info("ERROR : Exception: invalid properties format.", e.getMessage());
            throw new SAMLEngineException(e);
        } catch (IOException e) {
            LOG.info("ERROR : Exception: invalid file: " + fileConf, e.getMessage());
            throw new SAMLEngineException(e);
        } finally {
            IOUtils.closeQuietly(fileProperties);
        }
    }

    /**
     * Load cryptographic service provider.
     *
     * @throws SAMLEngineException the SAML engine exception
     */
    private final void loadCryptServiceProvider() throws SAMLEngineException {
        LOG.debug("Loading Encryption Cryptographic Service Provider");
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
            } else {
                LOG.debug("SAMLCore: Bouncy Castle provider already registered.");
            }

        } catch (Exception e) {
            LOG.error("ERROR : Error loading encryption CryptographicServiceProvider", e.getMessage());
            throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_LOAD_PROVIDER.errorCode(),PEPSErrors.SAML_ENGINE_LOAD_PROVIDER.errorMessage(), e);
        }
    }

    /**
     * Load encryption keystore.
     *
     * @throws SAMLEngineException the SAML engine exception
     */
    private final void loadKeystore() throws STORKSAMLEngineException {
        LOG.debug("Loading Encryption Keystore");
        InputStream fis = null;
        try {
            encryptionKeyStore = KeyStore.getInstance(properties
                    .getProperty(KEYSTORE_TYPE));

            LOG.debug("Loading KeyInfo from keystore file " + properties.getProperty(KEYSTORE_PATH));
            Object o=properties.get("keystorePath");
            if(o instanceof  String) {
                fis = new FileInputStream(o.toString());
            }else if(o instanceof BinaryParameter){
                fis = new ByteArrayInputStream((byte[])((BinaryParameter) o).getValue());
            }

            encryptionKeyStore.load(fis, properties.getProperty(KEY_STORE_PASS).toCharArray());

        } catch (Exception e) {
            throw new STORKSAMLEngineException(
                    PEPSErrors.SAML_ENGINE_INVALID_KEYSTORE.errorCode(),
                    PEPSErrors.SAML_ENGINE_INVALID_KEYSTORE.errorMessage(), e);
        } finally {
            IOUtils.closeQuietly(fis);
        }
    }

    private boolean isEnable(String key) {
        boolean value = false;
        if (null != encryptionActivationProperties) {
            try {
                value = Boolean.parseBoolean(encryptionActivationProperties.getProperty(key));
            }catch(Exception e){
                LOG.info("ERROR : Error retrieving activation value. {}", e);
            }
        }
        LOG.debug("Is active for: " + key + " : " + value);
        return value;
    }

    public boolean isModuleEncryptionEnable() {
        //The application should be smart enough to detect
        //the encrypted resposes and then apply decryption
        //to it.
        //I leave this parameters just in case future decissions
        //change this behaviour
        return true;
    }


    public boolean isEncryptionEnable(String countryCode) {
        LOG.debug("Loading encryption configuration");
        if(Boolean.parseBoolean(properties.getProperty(RESPONSE_ENCRYPTION_MANDATORY))){
            return true;
        }
        if(StringUtils.isEmpty(countryCode)) {
            LOG.info("ERROR : Country code is empty!");
            return false;
        }else {
            final String key = (new StringBuilder("EncryptTo.").append(countryCode)).toString();
            return isEnable(key);
        }
    }

    private Properties properties=new Properties();

    public void setProperty(String propName, String propValue){
        if(propValue==null){
            return;
        }
        properties.setProperty(propName, propValue);
        if(DATA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(propName) && !propValue.isEmpty()){
            samlAuthnResponseEncrypter.setDataEncAlgorithm(propValue);
        }
    }

    public Credential getEncryptionCredential() throws SAMLEngineException{
        Credential credential=null;
        try {
            final String serialNumber = properties.getProperty(SERIAL_NUMBER);
            final String issuer = properties.getProperty(RESPONSE_FROM_POINT_ISSUER);
            credential = SAMLEngineUtils.getEncryptionCredential(encryptionKeyStore, serialNumber,issuer);
        }catch (NoSuchAlgorithmException e) {
            throw new SAMLEngineException("A 'xmldsig#rsa-sha1' cryptographic algorithm is requested but is not available in the environment: " + e);
        } catch (KeyStoreException e) {
            throw new SAMLEngineException("Generic KeyStore exception:" + e);
        } catch (UnrecoverableKeyException e) {
            throw new SAMLEngineException("UnrecoverableKey exception:" + e);
        }
        return credential;

    }

    private EntityDescriptor getEntityFromMetadata(String metadataUrl) throws SAMLEngineException{
        if(metadataProcessor!=null && metadataUrl!=null && !metadataUrl.isEmpty()) {
            return metadataProcessor.getEntityDescriptor(metadataUrl);
        }
        return null;
    }
    private Credential getMetadataEncryptionCredential(RoleDescriptor rd)throws SAMLEngineException{
        for (KeyDescriptor kd : rd.getKeyDescriptors()) {
            if (kd.getUse() == UsageType.ENCRYPTION) {
                return SAMLEngineUtils.getKeyCredential(this, kd.getKeyInfo());
            }
        }
        return null;
    }
    public Credential getMetadataEncryptionCredential(String metadataUrl) throws SAMLEngineException{
        Credential credential=null;
        EntityDescriptor entity=getEntityFromMetadata(metadataUrl);
        if(entity==null || entity.getRoleDescriptors().isEmpty()){
            LOG.info("METADATA EXCEPTION : cannot retrieve entity descriptor from url "+metadataUrl);
        }else{
            for (RoleDescriptor rd : entity.getRoleDescriptors()) {
                if (rd instanceof SPSSODescriptor) {
                    credential=getMetadataEncryptionCredential(rd);
                    if (credential != null) {
                        break;
                    }
                }
            }
        }
        return credential;
    }

    private static final String DEFAULT_ALLOWED_ALGORITHMS="http://www.w3.org/2009/xmlenc11#aes128-gcm;http://www.w3.org/2009/xmlenc11#aes192-gcm;http://www.w3.org/2009/xmlenc11#aes256-gcm";
    private Set<String> getAllowedAlgorithms(){
        Set<String> allowed=new HashSet<String>();
        Pattern sepPattern = Pattern.compile(";");
        String whitelist = properties.getProperty(ENCRYPTION_ALGORITHM_WHITELIST);
        if(whitelist==null || whitelist.isEmpty()){
            whitelist=DEFAULT_ALLOWED_ALGORITHMS;
        }
        String[] wlAlgorithms = sepPattern.split(whitelist);
        if(wlAlgorithms!=null && wlAlgorithms.length>0) {
            for (String algo : wlAlgorithms){
                algo=algo.trim();
                if(!algo.isEmpty()){
                    allowed.add(algo);
                }
            }
        }
        return allowed.isEmpty()?null:allowed;
    }

    public String getJcaProviderName() {
        return jcaProviderName;
    }

    public void setJcaProviderName(String jcaProviderName) {
        this.jcaProviderName = jcaProviderName;
    }
}
