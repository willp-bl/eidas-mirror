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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.engine.SAMLEngineUtils;
import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.samlengineconfig.BinaryParameter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.*;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.exceptions.SAMLEngineException;


/**
 * The Class SWSign. Class responsible for signing and validating of messages
 * SAML with a certificate store software.
 * 
 * @author fjquevedo
 */
public class SignSW extends AbstractSigner {

    /**
     * The Constant KEYSTORE_TYPE.
     */
    private static final String KEYSTORE_TYPE = "keystoreType";

    /**
     * The Constant KEY_STORE_PASSWORD.
     */
    private static final String KEY_STORE_PASS = "keyStorePassword";

    /**
     * The logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SignSW.class
            .getName());

    /**
     * The stork own key store.
     */
    private KeyStore storkOwnKeyStore = null;

    MetadataProcessorI metadataProcessor = null;

    /**
     * Gets the stork own key store.
     *
     * @return the stork own key store
     */
    public final KeyStore getStorkOwnKeyStore() {
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
    public final void setStorkOwnKeyStore(final KeyStore newkOwnKeyStore) {
        this.storkOwnKeyStore = newkOwnKeyStore;
    }


    /**
     * Inits the file configuration.
     *
     * @param fileConf name of the file configuration
     * @throws SAMLEngineException error at the load from  file configuration
     */
    public final void init(final String fileConf)
            throws SAMLEngineException {
        InputStream fileProperties = null;
        try {
            fileProperties = SignSW.class.getResourceAsStream("/"
                    + fileConf);
            setProperties(new Properties());

            getProperties().loadFromXML(fileProperties);
            fileProperties.close();
        } catch (InvalidPropertiesFormatException e) {
            LOG.info("Exception: invalid properties format.");
            throw new SAMLEngineException(e);
        } catch (IOException e) {
            LOG.info("Exception: invalid file: " + fileConf);
            throw new SAMLEngineException(e);
        } finally {
            IOUtils.closeQuietly(fileProperties);
        }
    }

    public final void init(Properties props) {
        setProperties(props);
    }

    /**
     * @return the X509Certificate
     * @see eu.stork.peps.auth.engine.core.SAMLEngineSignI#getCertificate()
     */
    public final X509Certificate getCertificate() {
        throw new NotImplementedException();
    }


    /**
     * Sign the token SAML.
     *
     * @param tokenSaml the token SAML.
     * @return the SAML object
     * @throws SAMLEngineException the SAML engine exception
     */
    public final SAMLObject sign(final SignableSAMLObject tokenSaml)
            throws SAMLEngineException {
        LOG.trace("Start Sign process.");
        try {

            Signature signature = computeSignature(storkOwnKeyStore);
            tokenSaml.setSignature(signature);

            LOG.trace("Marshall samlToken.");
            Configuration.getMarshallerFactory().getMarshaller(tokenSaml).marshall(tokenSaml);

            LOG.trace("Sign samlToken.");
            Signer.signObject(signature);

        } catch (MarshallingException e) {
            LOG.info("ERROR : MarshallingException", e.getMessage());
            throw new SAMLEngineException(e);
        } catch (SignatureException e) {
            LOG.error("ERROR : Signature exception.", e.getMessage());
            throw new SAMLEngineException(e);
        }

        return tokenSaml;
    }


    private SAMLSignatureProfileValidator getSignatureProfileValidator(final SignableSAMLObject tokenSaml) throws SAMLEngineException {
        final SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
        try {
            // Indicates signature id conform to SAML Signature profile
            sigProfValidator.validate(tokenSaml.getSignature());
        } catch (ValidationException e) {
            LOG.info("ERROR : ValidationException: signature isn't conform to SAML Signature profile.", e.getMessage());
            throw new SAMLEngineException(e);
        }
        return sigProfValidator;
    }

    private void checkSignatureCertificate(final Signature signature, final List<Credential> trustCred) throws SAMLEngineException {
        checkSignatureCertificate(signature, trustCred, true);
    }

    private void checkSignatureCertificate(final Signature signature, final List<Credential> trustCred, boolean validate) throws SAMLEngineException {
        try {
            final X509Certificate cert=getSignatureCertificate(signature);
            // Exist only one certificate
            final BasicX509Credential entityX509Cred = new BasicX509Credential();
            entityX509Cred.setEntityCertificate(cert);

            checkTrust(entityX509Cred, trustCred);
            checkCertificateValidityPeriod(cert);
            checkCertificateIssuer(cert);
            LOG.trace("Key algorithm {}", SecurityHelper.getKeyAlgorithmFromURI(signature.getSignatureAlgorithm()));
            // Validate signature
            if (validate) {
                //DOM information related to the signature should be still available at this point
                final SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
                sigValidator.validate(signature);
            }
            if (!isAlgorithmAllowed(signature.getSignatureAlgorithm())) {
                LOG.info("ERROR : the algorithm {} used by the signature is not allowed", signature.getSignatureAlgorithm());
                throw new SAMLEngineException(PEPSErrors.INVALID_SIGNATURE_ALGORITHM.errorCode());
            }
        } catch (ValidationException e) {
            LOG.info("ERROR : ValidationException.", e.getMessage());
            throw new SAMLEngineException(e);
        }
    }

    private X509Certificate getSignatureCertificate(final Signature signature) throws SAMLEngineException{
        try {
            final KeyInfo keyInfo = signature.getKeyInfo();

            final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo
                    .getX509Datas().get(0).getX509Certificates().get(0);

            final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
            final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
            final X509Certificate cert = (X509Certificate) certFact.generateCertificate(bis);
            return cert;
        }catch (GeneralSecurityException e) {
            LOG.debug("ERROR : GeneralSecurityException.", e);
            LOG.warn("ERROR : GeneralSecurityException.", e.getMessage());
            throw new SAMLEngineException(e);
        }
    }

    /**
     * check metadata signature against the current trusted certificates
     * check @param tokenSaml against the certificate in the metadata
     * @param tokenSaml
     * @param trustCred
     * @throws SAMLEngineException
     */
    private void checkMetadata(final SignableSAMLObject tokenSaml, List<Credential> trustCred) throws SAMLEngineException {
        if (metadataProcessor != null) {
            String metadataUrl=null;
            Issuer issuer=null;
            boolean signatureChecked=false;
            if (tokenSaml instanceof AuthnRequest ) {
                issuer = ((AuthnRequest) tokenSaml).getIssuer();
            }else if(tokenSaml instanceof Response) {
                issuer = ((Response) tokenSaml).getIssuer();
            }
            if(issuer!=null){
                metadataUrl=issuer.getValue();
            }
            if(metadataUrl!=null && !metadataUrl.isEmpty()){
                EntityDescriptor entityDescriptor = metadataProcessor.getEntityDescriptor(metadataUrl);
                if(getProperties()==null || !getProperties().containsKey(PEPSValues.PEPS_METADATA_CHECK_SIGNATURE.toString()) ||
                        Boolean.parseBoolean(getProperties().getProperty(PEPSValues.PEPS_METADATA_CHECK_SIGNATURE.toString()))) {
                    metadataProcessor.checkValidMetadataSignature(metadataUrl, storkOwnKeyStore);
                }

                if (entityDescriptor != null && !entityDescriptor.getRoleDescriptors().isEmpty()) {
                    for (RoleDescriptor rd : entityDescriptor.getRoleDescriptors()) {
                        for (KeyDescriptor kd : rd.getKeyDescriptors()) {
                            if (kd.getUse() == UsageType.SIGNING) {
                                checkMetadataTrust(tokenSaml,kd.getKeyInfo());
                                signatureChecked=true;
                                break;
                            }
                        }
                    }
                }
                if(!signatureChecked){
                    //either the url of metadata is invalid or the content retrieed from the url does
                    //not contain the expected content (some RoleDescriptors)
                    throw new SAMLEngineException(PEPSErrors.SAML_ENGINE_INVALID_METADATA_SOURCE.errorCode(),PEPSErrors.SAML_ENGINE_INVALID_METADATA_SOURCE.errorMessage());
                }
            }
        }

    }

    private BasicX509Credential getKeyInfoCredential(KeyInfo keyInfo) throws CertificateException{
        final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo.getX509Datas().get(0).getX509Certificates().get(0);

        final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
        final X509Certificate cert = (X509Certificate) certFact.generateCertificate(bis);

        final BasicX509Credential entityX509Cred = new BasicX509Credential();
        entityX509Cred.setEntityCertificate(cert);
        return entityX509Cred;
    }

    /**
     *
     * @param tokenSaml the object whose signature has to be checked
     * @param keyInfo the keyinfo retrieved from saml metadata
     * @throws SAMLEngineException
     */
    private void checkMetadataTrust(final SignableSAMLObject tokenSaml, KeyInfo keyInfo) throws SAMLEngineException{
        try {
            final List<Credential> metadataCred = new ArrayList<Credential>();

            metadataCred.add(getKeyInfoCredential(keyInfo));
            final X509Certificate currentSignatureCert=getSignatureCertificate(tokenSaml.getSignature());
            final BasicX509Credential currentSignatureX509Cred = new BasicX509Credential();
            currentSignatureX509Cred.setEntityCertificate(currentSignatureCert);

            checkTrust(currentSignatureX509Cred, metadataCred);
            checkSignatureCertificate(tokenSaml.getSignature(), metadataCred, true);
        } catch (CertificateException ce) {
            LOG.warn("ERROR : error creating certificate instance", ce.getMessage());
            LOG.debug("ERROR : error creating certificate instance", ce);
            throw new SAMLEngineException(ce);
        }

    }

    /**
     * @param tokenSaml token SAML
     * @return the SAMLObject validated.
     * @throws SAMLEngineException error validate signature
     * @see eu.stork.peps.auth.engine.core.SAMLEngineSignI#validateSignature(org.opensaml.common.SignableSAMLObject)
     */
    public final SAMLObject validateSignature(final SignableSAMLObject tokenSaml)
            throws SAMLEngineException {
        LOG.debug("Start signature validation.");
        // Validate structure signature
        getSignatureProfileValidator(tokenSaml);

        final List<Credential> trustCred = SAMLEngineUtils.getListOfCredential(storkOwnKeyStore);

        if(metadataProcessor==null){
            checkSignatureCertificate(tokenSaml.getSignature(), trustCred);
        } else {
            checkMetadata(tokenSaml, trustCred);
        }
        return tokenSaml;
    }

    public void setMetadataProcessor(MetadataProcessorI processor) {
        metadataProcessor = processor;
    }

    /**
     * Load cryptographic service provider.
     *
     * @throws SAMLEngineException the SAML engine exception
     */
    public final void loadCryptServiceProvider() throws SAMLEngineException {
        LOG.info("Load Cryptographic Service Provider");
        InputStream fis = null;
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
                Security.insertProviderAt(new BouncyCastleProvider(), 0);
            }

            storkOwnKeyStore = KeyStore.getInstance(getProperties().getProperty(KEYSTORE_TYPE));

            LOG.debug("Loading KeyInfo from keystore file " + getProperties().getProperty("keystorePath"));
            Object o=getProperties().get("keystorePath");
            //CAVEAT: stores accessed through BinaryParameter are loaded when SAMLEngine configuration is (re)loaded
            if(o instanceof  String) {
                fis = new FileInputStream(o.toString());
            }else if(o instanceof BinaryParameter){
                fis = new ByteArrayInputStream((byte[])((BinaryParameter) o).getValue());
            }

            storkOwnKeyStore.load(fis, getProperties().getProperty(KEY_STORE_PASS).toCharArray());

        } catch (Exception e) {
            LOG.info("ERROR : Error loading CryptographicServiceProvider", e.getMessage());
            LOG.debug("ERROR : Error loading CryptographicServiceProvider", e);
            throw new SAMLEngineException("Error loading CryptographicServiceProvider", e);
        } finally {
            IOUtils.closeQuietly(fis);
        }
    }


    /**
     * Validate against trust certificate
     * @param entityX509Cred
     * @param trustCred
     * @throws SAMLEngineException
     */
    private void checkTrust(BasicX509Credential entityX509Cred, List<Credential> trustCred) throws SAMLEngineException{
        SAMLEngineUtils.checkTrust(entityX509Cred, trustCred);
    }

    /**
     * @return the signature algorithm to be used when signing
     */
    @Override
    protected String getSignatureAlgorithmForSign() {
        String signatureAlgorithmName = getProperties().getProperty(SIGNATURE_ALGORITHM);
        return SAMLEngineUtils.validateSigningAlgorithm(signatureAlgorithmName);
    }


    /**
     * stores the list of allowed algorithm
     */
    Set<String> algoWhiteList = new HashSet<String>();

    //check if the current algorithm is whitelisted
    private boolean isAlgorithmAllowed(String signatureAlgorithm) {
        boolean allowed = true;
        if (checkAlgorithm()) {
            String whiteList = getProperties().getProperty(SIGNATURE_ALGORITHMS_WHITELIST).trim();
            if (algoWhiteList.isEmpty() && !whiteList.isEmpty()) {
                algoWhiteList = getAlgorithmList(whiteList);
            }
            allowed = algoWhiteList.contains(signatureAlgorithm);
        }
        return allowed;
    }

    private boolean checkAlgorithm() {
        String whiteList = getProperties().getProperty(SIGNATURE_ALGORITHMS_WHITELIST);
        return whiteList != null;
    }

    private static final String[] KNOWN_OPENSAML_ALGORITMS = {
            SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
            SignatureConstants.ALGO_ID_SIGNATURE_RSA_RIPEMD160,
            SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256, SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA384, SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512,};

    static {
        Arrays.sort(KNOWN_OPENSAML_ALGORITMS);
    }
    private Set<String> getAlgorithmList(String whiteList){
        Set<String> configuredAlgorithms = PEPSUtil.parseSemicolonSeparatedList(whiteList);
        Set<String> algorithms=new HashSet<String>();
            for(String algorithm:configuredAlgorithms){
                if(Arrays.binarySearch(KNOWN_OPENSAML_ALGORITMS, algorithm)>=0){
                    algorithms.add(algorithm);
                    continue;
                }
            }
        return algorithms;
    }
}
