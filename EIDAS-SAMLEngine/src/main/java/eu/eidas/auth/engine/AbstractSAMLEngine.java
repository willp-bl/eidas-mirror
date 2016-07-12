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

package eu.eidas.auth.engine;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import eu.eidas.auth.commons.DocumentBuilderFactoryUtil;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.engine.core.SAMLEngineEncryptionI;
import eu.eidas.auth.engine.core.SAMLEngineSignI;
import eu.eidas.auth.engine.core.EIDASSAMLCore;
import eu.eidas.auth.engine.core.impl.EncryptionModuleFactory;
import eu.eidas.auth.engine.core.impl.SignModuleFactory;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.configuration.ConfigurationCreator;
import eu.eidas.configuration.ConfigurationReader;
import eu.eidas.configuration.InstanceEngine;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineRuntimeException;
import eu.eidas.samlengineconfig.CertificateConfigurationManager;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.commons.lang.StringUtils;

/**
 * Class that wraps the operations over SAML tokens, both generation and
 * validation of SAML requests and SAML responses. Compliant with "OASIS Secure
 * Assertion Markup Language (SAML) 2.0, May 2005", but taking into account
 * EIDAS specific requirements.
 *
 * @author fjquevedo
 * @author iinigo
 */

public abstract class AbstractSAMLEngine {
    /*Dedicated marker for the SAML exchanges*/
    public static final Marker SAML_EXCHANGE = MarkerFactory.getMarker("SAML_EXCHANGE");
    /**
     * The instance of every engine SAML.
     */
    private static Map<String, Map<String, InstanceEngine>> instanceConfigs;

    /**
     * The instances of SAML engine.
     */
    private static Map<String, Map<String, Map<String, Object>>> instances;

    protected static final String DEFAULT_CONFIG_NAME = "default";

    /**
     * The logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AbstractSAMLEngine.class
            .getName());

    /**
     * The Constant MODULE_SIGN_CONF.
     */
    private static final String MODULE_SIGN_CONF = "SignatureConf";

    /**
     * The Constant MODULE_ENCRYPTION_CONF.
     */
    private static final String MODULE_ENCRYPTION_CONF = "EncryptionConf";

    /**
     * The Constant SAML_ENGINE_SIGN_CLASS.
     */
    private static final String SAML_ENGINE_SIGN_CLASS = "class";

    /**
     * The Constant SAML_ENGINE_ENCRYPTION_CLASS.
     */
    private static final String SAML_ENGINE_ENCRYPTION_CLASS = "class";

    /**
     * The Constant SAML_ENGINE_CONF.
     */
    private static final String SAML_ENGINE_CONF = "SamlEngineConf";

    /**
     * The Constant SAML_ENGINE_FILE_CONF.
     */
    private static final String SAML_ENGINE_FILE_CONF = "fileConfiguration";

    /**
     * The codification of characters.
     */
    private static final String CHARACTER_ENCODING = "UTF-8";

    /**
     * The SAML core.
     */
    private EIDASSAMLCore samlCore;

    /**
     * The Module of Signature.
     */
    private SAMLEngineSignI signer;

    /**
     * The Module of Encryption.
     */
    private SAMLEngineEncryptionI cipher;

    /**
     * whether the response encryption is mandatory or not
     */
    private boolean mandatoryResponseEncryption=false;

    protected String instanceName;

    // See http://stackoverflow.com/questions/9828254/is-documentbuilderfactory-thread-safe-in-java-5
    // See also org.opensaml.xml.parse.ParserPool -- Code removed : private static DocumentBuilderFactory dbf = null
    /**
     * The Document Builder Factory.
     */
    private static final Queue<DocumentBuilderFactory> DOCUMENT_BUILDER_FACTORY_POOL = new ConcurrentLinkedQueue<DocumentBuilderFactory>();
    private static final Queue<DocumentBuilder> DOCUMENT_BUILDER_POOL = new ConcurrentLinkedQueue<DocumentBuilder>();

    private static final Queue<TransformerFactory> TRANSFORMER_FACTORY_POOL = new ConcurrentLinkedQueue<TransformerFactory>();
    private static final Queue<Transformer> TRANSFORMER_POOL = new ConcurrentLinkedQueue<Transformer>();

    //Country code used to encrypt the response sent
    private String countryRespondTo;
    //Country code used to decrypt the response received
    private String countryResponseFrom;
    private String requestIssuer;

    public String getRequestIssuer() {
        return requestIssuer;
    }

    public void setRequestIssuer(String requestIssuer) {
        this.requestIssuer = requestIssuer;
    }

    public static DocumentBuilderFactory newDocumentBuilderFactory() {
        try {
            return DocumentBuilderFactoryUtil.getSecureDocumentBuilderFactory();
        } catch (ParserConfigurationException e) {
            LOG.error("Error parser configuration in Load of documentBuilderFactory.");
            throw new EIDASSAMLEngineRuntimeException(e);
        }
    }

    /** Initializes the SAML engine. */
    /** Configure Document Builder Factory. */

    static {
        instanceConfigs = new HashMap<String, Map<String, InstanceEngine>>();
        instances = new HashMap<String, Map<String, Map<String, Object>>>();
    }

    /**
     * Method that initializes the basic services for the SAML Engine, like the
     * OpenSAML library and the BouncyCastle provider.
     */
    private static void startUp(String name, CertificateConfigurationManager configManager) {

        LOG.trace("SAMLEngine: Initialize OpenSAML");
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            LOG.error("Problem initializing the OpenSAML library.");
            throw new EIDASSAMLEngineRuntimeException(e);
        }

        LOG.trace("Read all file configurations. (instances of SAMLEngine)");
        Map<String, InstanceEngine> engineInstances = instanceConfigs.get(name);
        if (null == engineInstances) {
            loadConfig(name, configManager);
        }

    }

    private static void loadConfig(String name, CertificateConfigurationManager configManager) {
        Map<String, InstanceEngine> engineInstances = null;
        try {
            synchronized (AbstractSAMLEngine.class) {
                if(configManager!=null) {
                    engineInstances = ConfigurationReader.readConfiguration(configManager);
                }
                if(configManager==null || engineInstances==null || engineInstances.isEmpty()) {
                    engineInstances = ConfigurationReader.readConfiguration();
                }
                instanceConfigs.put(name, engineInstances);
            }
        } catch (SAMLEngineException e) {
            LOG.error("Error read configuration file.");
            throw new EIDASSAMLEngineRuntimeException(e);
        }
        LOG.trace("Create all instances of saml engine. (instances of SAMLEngine)");
        try {
            Map<String, Map<String, Object>> instanceParameters;
            if (configManager == null) {
                instanceParameters = ConfigurationCreator.createConfiguration(engineInstances);
            } else {
                instanceParameters = ConfigurationReader.getInstanceParameters(engineInstances, configManager);
            }
            instances.put(name, instanceParameters);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error initializing instances from Eidas SAML engine.");
            throw new EIDASSAMLEngineRuntimeException(e);
        }

    }

    /**
     * Instantiates a new SAML engine.
     */
    private AbstractSAMLEngine() {

    }

    protected AbstractSAMLEngine(final String nameInstance)
            throws EIDASSAMLEngineException {
        this(nameInstance, DEFAULT_CONFIG_NAME, null);
    }

    /**
     * Instantiates a new SAML engine.
     *
     * @param nameInstance the name instance
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    protected AbstractSAMLEngine(final String nameInstance, final String configName, final CertificateConfigurationManager configManager)
            throws EIDASSAMLEngineException {
        this.instanceName = nameInstance;
        LOG.debug("Loading Specific Configuration.");

        LOG.debug("Create intance of saml messages.");
        if (!instances.containsKey(configName)) {
            synchronized (AbstractSAMLEngine.class) {
                if (!instances.containsKey(configName)) {
                    startUp(configName, configManager);
                }
            }
        } else if (instanceConfigs.get(configName).isEmpty()) {
            synchronized (AbstractSAMLEngine.class) {
                loadConfig(configName, configManager);
            }
        }

        if (!instances.containsKey(configName)) {
            LOG.error("loading config " + configName);

            throw new EIDASSAMLEngineException(
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage()),
                            "loading config " + configName);
        }

        Map<String, Object> instance = instances.get(configName).get(nameInstance);

        if (instance == null || instance.isEmpty()) {
            LOG.error("Instance: " + nameInstance + " not exist.");
            throw new EIDASSAMLEngineException(
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage()), "Instance: " + nameInstance + " not exist.");
        }

        Properties properties = (Properties) instance.get(SAML_ENGINE_CONF);

        if (properties == null) {
            LOG.error("SamlEngine.xml: not exist.");
            throw new EIDASSAMLEngineException(
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage()), "SamlEngine.xml: not exist.");
        }

        samlCore = new EIDASSAMLCore(properties);

        final Map<String, Object> propertiesSign = (HashMap<String, Object>) instance.get(MODULE_SIGN_CONF);

        LOG.debug("Loading Module of sign.");
        signer = SignModuleFactory.getInstance(propertiesSign.get(SAML_ENGINE_SIGN_CLASS).toString());

        try {
            LOG.info("Initialize module of sign.");
            if (configManager == null) {
                signer.init(propertiesSign.get(SAML_ENGINE_FILE_CONF).toString());
            } else {
                //the props are already read
                signer.init((Properties) propertiesSign.get(SAML_ENGINE_FILE_CONF));
            }
            LOG.info("Load cryptographic service provider of module of sign.");
            signer.loadCryptServiceProvider();
        } catch (SAMLEngineException e) {
            LOG.error("Error create signature module: " + propertiesSign.get(SAML_ENGINE_FILE_CONF));
            LOG.info("Exception",e);
            throw new EIDASSAMLEngineException(
                    EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorCode(),
                    EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR.errorMessage(), e);
        }

        // LOADING ENCRYPTION CONFIGURATION
        final Map<String, Object> propertiesEncryption = (HashMap<String, Object>) instance.get(MODULE_ENCRYPTION_CONF);

        if (propertiesEncryption == null) {
            LOG.info("ERROR : Encryption module configuration not found. SAML Engine  '" + nameInstance + "' in non-encryption mode!");
        } else {
            try {
                LOG.info("Loading Encryption for " + nameInstance);

                cipher = EncryptionModuleFactory.getInstance(propertiesEncryption
                        .get(SAML_ENGINE_ENCRYPTION_CLASS).toString());
                Object samlEngineConf = propertiesEncryption.get(SAML_ENGINE_FILE_CONF);
                if (samlEngineConf instanceof String) {
                    cipher.init((String) samlEngineConf);
                }else if (samlEngineConf instanceof Properties) {
                    cipher.init((Properties) samlEngineConf);
                } else {
                    LOG.error("Unknown configuration");
                }
            } catch (Exception e) {
                cipher = null;
                LOG.error("Encryption Module could not be loaded! SAML Engine '" + nameInstance + "' in non-encryption mode!", e);
            }
        }
    }


    /**
     * Returns if the response should be encrypted
     *
     * @return true if encryption is on / false if encrytpion is off.
     */
    protected boolean encryptResponse() {
        return null != cipher && requestIssuer != null;
    }

    /**
     * Returns if the response should be decrypted
     *
     * @return
     */
    protected boolean decryptResponse() {
        return null != cipher ? cipher.isModuleEncryptionEnable() : false;
    }

    /**
     * Gets the Encrypter.
     */
    protected SAMLEngineEncryptionI getCipher() {
        return cipher;
    }

    /**
     * Gets the Signer properties.
     *
     * @return the SAML Sign properties
     */
    protected SAMLEngineSignI getSigner() {
        return signer;
    }

    public void setSignerProperty(String propName, String propValue) {
        if (signer != null && propName != null && propValue != null) {
            signer.setProperty(propName, propValue);
        } else {
            LOG.error("Configuration error - Unable to set signer property - signer {} propertyName {} value {} not set", signer, propName, propValue);
        }
    }

    /**
     * Gets the SAML core properties.
     *
     * @return the SAML core properties
     */
    public final EIDASSAMLCore getSamlCoreProperties() {
        return samlCore;
    }

    /**
     * Method that transform the received SAML object into a byte array
     * representation.
     *
     * @param samlToken the SAML token.
     * @return the byte[] of the SAML token.
     * @throws SAMLEngineException the SAML engine exception
     */
    private byte[] marshall(final XMLObject samlToken)
            throws SAMLEngineException {

        try {
            final MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

            final Marshaller marshaller = marshallerFactory.getMarshaller(samlToken);

            // See http://stackoverflow.com/questions/9828254/is-documentbuilderfactory-thread-safe-in-java-5
            DocumentBuilder documentBuilder = DOCUMENT_BUILDER_POOL.poll();
            if (documentBuilder == null) {
                DocumentBuilderFactory documentBuilderFactory = DOCUMENT_BUILDER_FACTORY_POOL.poll();
                if (documentBuilderFactory == null) {
                    documentBuilderFactory = newDocumentBuilderFactory();
                }
                documentBuilder = documentBuilderFactory.newDocumentBuilder();
                DOCUMENT_BUILDER_FACTORY_POOL.offer(documentBuilderFactory);
            }
            final Document doc = documentBuilder.newDocument();

            marshaller.marshall(samlToken, doc);

            // Obtain a byte array representation of the marshalled SAML object
            final DOMSource domSource = new DOMSource(doc);
            final StringWriter writer = new StringWriter();
            final StreamResult result = new StreamResult(writer);

            // See http://stackoverflow.com/questions/9828254/is-documentbuilderfactory-thread-safe-in-java-5
            Transformer transformer = TRANSFORMER_POOL.poll();
            if (transformer == null) {
                TransformerFactory transformerFactory = TRANSFORMER_FACTORY_POOL.poll();
                if (transformerFactory == null) {
                    transformerFactory = TransformerFactory.newInstance();
                }
                transformer = transformerFactory.newTransformer();
                TRANSFORMER_FACTORY_POOL.offer(transformerFactory);
            }

            transformer.transform(domSource, result);
            LOG.debug("SAML request \n" + writer.toString());
            return writer.toString().getBytes(CHARACTER_ENCODING);

        } catch (ParserConfigurationException e) {
            LOG.error("ParserConfigurationException.", e.getMessage());
            throw new SAMLEngineException(e);
        } catch (MarshallingException e) {
            LOG.info("ERROR : MarshallingException.", e.getMessage());
            throw new SAMLEngineException(e);
        } catch (TransformerConfigurationException e) {
            LOG.info("ERROR : TransformerConfigurationException.", e.getMessage());
            throw new SAMLEngineException(e);
        } catch (TransformerException e) {
            LOG.info("ERROR : TransformerException.", e.getMessage());
            throw new SAMLEngineException(e);
        } catch (UnsupportedEncodingException e) {
            LOG.error("ERROR : UnsupportedEncodingException: " + CHARACTER_ENCODING, e.getMessage());
            throw new SAMLEngineException(e);
        }
    }

    /**
     * Method that signs a SAML Token.
     *
     * @param tokenSaml the token SAML
     * @return the SAML object sign
     * @throws SAMLEngineException the SAML engine exception
     */
    protected SignableSAMLObject sign(final SignableSAMLObject tokenSaml, String messageFormat)
            throws SAMLEngineException {
        SignableSAMLObject tokenSamlToSign = tokenSaml;
        if (tokenSamlToSign instanceof Response) {
            // ENCRYPT THE SAMLObject BEFORE SIGN
            if(this.encryptResponse() && !SAMLEngineUtils.isErrorSamlResponse((Response)tokenSamlToSign) ) {
                LOG.debug("Encryption Executing...");
                tokenSamlToSign = getCipher().encryptSAMLResponse((Response) tokenSamlToSign, getCountryRespondTo(), getRequestIssuer(), messageFormat);
                LOG.debug("Encryption finished: " + tokenSamlToSign);
            }else if(!SAMLEngineUtils.isErrorSamlResponse((Response)tokenSamlToSign)){
                 checkUnencryptedResponsesAllowed();
            }
        }
        // SIGN
        LOG.debug("Sign SamlToken.");
        signer.sign(tokenSamlToSign);
        return tokenSamlToSign;
    }

    /**
     * check whether the unencrypted responses are allowed
     * @throws SAMLEngineException
     */
    private void checkUnencryptedResponsesAllowed()throws SAMLEngineException{
        if(isMandatoryResponseEncryption()){
            throw new SAMLEngineException(EIDASErrors.SAML_ENGINE_UNENCRYPTED_RESPONSE.errorCode(), EIDASErrors.SAML_ENGINE_UNENCRYPTED_RESPONSE.errorMessage());
        }
    }

    /**
     * Sign and transform to byte array.
     *
     * @param samlToken the SAML token
     * @return the byte[] of the SAML token
     * @throws SAMLEngineException the SAML engine exception
     */
    protected final byte[] signAndMarshall(final SignableSAMLObject samlToken, final String messageFormat)
            throws SAMLEngineException {
        LOG.debug("Marshall Saml Token.");
        SignableSAMLObject signElement = sign(samlToken, messageFormat);
        return marshall(signElement);
    }

    /**
     * Build the default set of parser features to use.
     * The default features set are:
     * <ul>
     * <li>{@link javax.xml.XMLConstants#FEATURE_SECURE_PROCESSING} = true</li>
     * <li>http://apache.org/xml/features/disallow-doctype-decl = true</li>
     * Reference : https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
     * </ul>
     */
    protected static Map<String, Boolean> buildDefaultFeature() {
        Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);

        // Ignore the external DTD completely
        // Note: this is for Xerces only:
        features.put("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
        // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented
        // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
        features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);

        // If you can't completely disable DTDs, then at least do the following:
        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);

        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);

        return features;
    }

    public static BasicParserPool getNewBasicSecuredParserPool() {
        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        // Note: this is necessary due to an unresolved Xerces deferred DOM issue/bug
        ppMgr.setBuilderFeatures(buildDefaultFeature());
        ppMgr.setNamespaceAware(true);
        return ppMgr;
    }

    private XMLObject performUnmarshall(final UnmarshallerFactory unmarshallerFact, final Element root) throws SAMLEngineException {
        final Unmarshaller unmarshaller = unmarshallerFact.getUnmarshaller(root);
        try {
            return unmarshaller.unmarshall(root);
        } catch (NullPointerException e) {
            LOG.info("ERROR : element tag incomplet or null.");
            throw new SAMLEngineException("NullPointerException", e);
        } catch (UnmarshallingException e) {
            LOG.info("ERROR : TransformerException.", e.getMessage());
            LOG.debug("ERROR : TransformerException.", e);
            throw new SAMLEngineException(e);
        }

    }

    /**
     * Method that unmarshalls a SAML Object from a byte array representation to
     * an XML Object.
     *
     * @param samlToken Byte array representation of a SAML Object
     * @return XML Object (superclass of SAMLObject)
     * @throws SAMLEngineException the SAML engine exception
     */
    protected final XMLObject unmarshall(final byte[] samlToken)
            throws SAMLEngineException {
        try {
            // Get parser pool manager
            final BasicParserPool ppMgr = getNewBasicSecuredParserPool();

            // Parse SAMLToken
            Document document = ppMgr.parse(new ByteArrayInputStream(samlToken));
            if (document != null) {
                final Element root = document.getDocumentElement();
                // Get appropriate unmarshaller
                final UnmarshallerFactory unmarshallerFact = Configuration.getUnmarshallerFactory();
                // Unmarshall using the SAML Token root element
                if (unmarshallerFact != null && root != null) {
                    return performUnmarshall(unmarshallerFact, root);
                } else {
                    LOG.info("ERROR : Error element tag incomplet or null.");
                    throw new SAMLEngineException("NullPointerException : unmarshallerFact or root is null");
                }
            } else {
                LOG.info("ERROR : Error element tag incomplet or null.");
                throw new SAMLEngineException("NullPointerException : document is null");
            }
        } catch (XMLParserException e) {
            LOG.info("XML Parsing Error.", e.getMessage());
            LOG.debug("XML Parsing Error.", e);
            throw new SAMLEngineException(e);
        }
    }

    /**
     * Method that validates an XML Signature contained in a SAML Token.
     *
     * @param samlToken the SAML token
     * @return the SAML object
     * @throws SAMLEngineException the SAML engine exception
     */
    protected final SAMLObject validateSignature(
            final SignableSAMLObject samlToken, String messageFormat) throws SAMLEngineException {

        LOG.debug("Validate Signature");
        signer.validateSignature(samlToken, messageFormat);

        SignableSAMLObject tokenSamlDecrypted = samlToken;
        if (this.decryptResponse() && samlToken instanceof Response && !((Response) samlToken).getEncryptedAssertions().isEmpty()) {
            // DECRYPT THE SAMLObject AFTER VALIDATION
            LOG.debug("Decryption Executing...");
            tokenSamlDecrypted = this.getCipher().decryptSAMLResponse((Response) samlToken, getCountryResponseFrom());
            if (LOG.isTraceEnabled()) {
                LOG.trace("Decryption finished: " + new String(marshall(tokenSamlDecrypted), Charset.defaultCharset()));
            } else {
                LOG.debug("Decryption finished.");
            }
        }else if(samlToken instanceof Response && (StatusCode.SUCCESS_URI.equals(((Response) samlToken).getStatus().getStatusCode().getValue()))){
            checkUnencryptedResponsesAllowed();
        }
        return tokenSamlDecrypted;
    }

    protected final byte[] noSignAndMarshall(final SignableSAMLObject samlToken)
            throws SAMLEngineException {
        LOG.debug("Marshall Saml Token.");
        return marshall(samlToken);
    }

    public String getCountryRespondTo() {
        return countryRespondTo;
    }

    public void setCountryRespondTo(String countryRespondTo) {
        this.countryRespondTo = countryRespondTo;
    }

    public String getCountryResponseFrom() {
        return countryResponseFrom;
    }

    public void setCountryResponseFrom(String countryResponseFrom) {
        this.countryResponseFrom = countryResponseFrom;
    }

    public void setEncrypterProperty(String propName, String propValue) {
        if (cipher != null && propName != null && propValue != null) {
            cipher.setProperty(propName, propValue);
        } else {
            LOG.error("Configuration error - Unable to set encrypter property - cipher {} propertyName {} value {} not set", cipher, propName, propValue);
        }
    }

    public Signature getSignature() throws SAMLEngineException {
        return signer == null ? null : signer.computeSignature(signer.getTrustStore());
    }

    public Credential getSigningCredential() throws SAMLEngineException {
        return signer == null ? null : signer.getPublicSigningCredential(signer.getTrustStore());
    }

    public Credential getEncryptionCredential() throws SAMLEngineException {
        return cipher == null ? null : cipher.getEncryptionCredential();
    }

    public void setMetadataProcessor(MetadataProcessorI processor) {
        signer.setMetadataProcessor(processor);
        if (cipher != null) {
            cipher.setMetadataProcessor(processor);
        }
    }

    public void signDescriptor(SSODescriptor descriptor) throws SAMLEngineException{
        signer.sign(descriptor);
    }

    public void signEntityDescriptor(EntityDescriptor descriptor) throws SAMLEngineException{
        signer.signMetadata(descriptor);
    }

    public byte[] signAndMarshallEntitiesDescriptor(EntitiesDescriptor descriptor) throws SAMLEngineException{
        signer.signMetadata(descriptor);
        return marshall(descriptor);

    }

    public boolean isMandatoryResponseEncryption() {
        return mandatoryResponseEncryption;
    }

    public void setMandatoryResponseEncryption(String mandatoryResponseEncryption) {
        if(cipher!=null && StringUtils.isNotBlank(mandatoryResponseEncryption)){
            this.mandatoryResponseEncryption = Boolean.parseBoolean(mandatoryResponseEncryption);
            cipher.setProperty(SAMLEngineEncryptionI.RESPONSE_ENCRYPTION_MANDATORY, mandatoryResponseEncryption);
        } else {
            LOG.error("Configuration error - Unable to set mandatory response encryption property - cipher is null or parameter mandatoryResponseEncryption {} is null", cipher, mandatoryResponseEncryption);
        }
    }
}
