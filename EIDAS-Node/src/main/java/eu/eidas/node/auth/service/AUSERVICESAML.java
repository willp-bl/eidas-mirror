/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations 
 * under the License.
 */
package eu.eidas.node.auth.service;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.auth.engine.metadata.MetadataUtil;
import eu.eidas.auth.specific.ITranslatorService;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.node.init.EidasSamlEngineFactory;
import eu.eidas.node.logging.LoggingMarkerMDC;
import eu.eidas.node.utils.EidasNodeErrorUtil;
import eu.eidas.node.utils.EidasNodeValidationUtil;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;

import java.util.Locale;

/**
 * This class is used by {@link AUSERVICE} to get, process and generate SAML
 * Tokens. Also, it checks attribute values and mandatory attributes.
 *
 * @see ISERVICESAMLService
 */
public class AUSERVICESAML implements ISERVICESAMLService {

    /**
     * Connector's Util class.
     */
    protected AUSERVICEUtil serviceUtil;

    /**
     * Logger object.
     */
    protected static final Logger LOGGER = LoggerFactory.getLogger(AUSERVICESAML.class
            .getName());

    /**
     * Request logging.
     */
    private static final Logger LOGGER_COM_REQ = LoggerFactory
            .getLogger(EIDASValues.EIDAS_PACKAGE_REQUEST_LOGGER_VALUE.toString() + "."
                    + AUSERVICE.class.getSimpleName());

    /**
     * Response logging.
     */
    protected static final Logger LOGGER_COM_RESP = LoggerFactory
            .getLogger(EIDASValues.EIDAS_PACKAGE_RESPONSE_LOGGER_VALUE.toString() + "."
                    + AUSERVICE.class.getSimpleName());

    /**
     * Logger bean.
     */
    private IEIDASLogger loggerBean;

    /**
     * Specific interface.
     */
    private ITranslatorService specificNode;

    /**
     * Instance of SAML Engine.
     */
    private String samlInstance;

    public String getSamlEngineInstanceName(){
        return samlInstance;
    }

    public void setSamlEngineInstanceName(String samlEngineInstanceName){
        samlInstance=samlEngineInstanceName;
    }

    /**
     * Country Code of this ProxyService.
     */
    private String countryCode;

    /**
     * Minimum QAA Level Allowed.
     */
    private int minQAA;

    /**
     * Maximum QAA Level Allowed.
     */
    private int maxQAA;

    /**
     * Max QAA Level that this ProxyService can authenticate.
     */
    private int maxQAAlevel;

    /**
     * Resource bundle to get error messages.
     */
    private MessageSource messageSource;

    private long skewTime;

    private EidasSamlEngineFactory samlEngineFactory;

    private String serviceMetadataUrl;
    private String serviceRequesterMetadataUrl;
    private MetadataProcessorI metadataProcessor;

    public long getSkewTime() {
        return skewTime;
    }

    public void setSkewTime(long skewTime) {
        this.skewTime = skewTime;
    }

    public EidasSamlEngineFactory getSamlEngineFactory() {
        return samlEngineFactory;
    }

    public void setSamlEngineFactory(EidasSamlEngineFactory samlEngineFactory) {
        this.samlEngineFactory = samlEngineFactory;
    }

    /**
     * {@inheritDoc}
     */
    public void checkMandatoryAttributes(final EIDASAuthnRequest authnData,
                                         final String ipUserAddress) {
        if (authnData==null || !AttributeUtil.checkMandatoryAttributes(authnData.getPersonalAttributeList())) {
            LOGGER.info("BUSINESS EXCEPTION : Mandatory attribute is missing!");
            final byte[] error =
                    generateErrorAuthenticationResponse(authnData, EIDASUtil
                            .getConfig(EIDASErrors.ATT_VERIFICATION_MANDATORY.errorCode()),
                            EIDASSubStatusCode.REQUEST_DENIED_URI.toString(), EIDASUtil
                            .getConfig(EIDASErrors.ATT_VERIFICATION_MANDATORY.errorMessage()),
                            ipUserAddress, true);
            if (LOGGER.isInfoEnabled()){
                LOGGER.info("Missing attributes: " + AttributeUtil.getMissingMandatoryAttributes(authnData.getPersonalAttributeList()));
            }
            throw new EIDASServiceException(
                    EIDASUtil.encodeSAMLToken(error),
                    EIDASUtil.getConfig(EIDASErrors.ATT_VERIFICATION_MANDATORY.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.ATT_VERIFICATION_MANDATORY.errorMessage()));
        }
    }
    
    /**
     * {@inheritDoc}
     */
    public void validateAPResponses(EIDASAuthnRequest authData, IEIDASSession session, String ipUserAddr){
    	validateResponseLoA(session, authData);
    }
    /**
     * checks LoA coming from IdP against that in the request
     * if IdP provided no LoA, than LoA from ProxyService will be used (for this, authData's loa is set to null)
     * @param session
     * @param authData
     */
    private void validateResponseLoA(IEIDASSession session, EIDASAuthnRequest authData){
        if(session.containsKey(EIDASParameters.EIDAS_SERVICE_LOA.toString()) && serviceUtil.isEIDAS10(authData.getMessageFormatName())){
            if(!EidasNodeValidationUtil.isLoAValid(authData.getEidasLoACompareType(), authData.getEidasLoA(), (String)session.get(EIDASParameters.EIDAS_SERVICE_LOA.toString()))){
                final String exErrorCode = EIDASUtil.getConfig(EIDASErrors.INVALID_RESPONSE_LOA_VALUE.errorCode());
                final String exErrorMessage = EIDASUtil.getConfig(EIDASErrors.INVALID_RESPONSE_LOA_VALUE.errorMessage());
                throw new EIDASServiceException(null, exErrorCode, exErrorMessage);
            }
            authData.setEidasLoA((String)session.get(EIDASParameters.EIDAS_SERVICE_LOA.toString()));
        }else{
            authData.setEidasLoA(null);
        }
    }

    /**
     * {@inheritDoc}
     */
    public byte[] generateAuthenticationResponse(
            final EIDASAuthnRequest authData, final String ipUserAddress,
            final boolean isConsent) {
        EIDASSAMLEngine engine=null;
        try {
             engine= getSamlEngineFactory().getEngine(getSamlEngineInstanceName(), getServiceUtil() == null ? null : getServiceUtil()
                     .getConfigs());
            engine.setRequestIssuer(authData.getIssuer());
            LOGGER.trace("check assertion consumer url of the partner requesting this");
            LOGGER.info(LoggingMarkerMDC.SAML_EXCHANGE, "ProxyService - Generating SAML Response to request with ID {}", authData.getSamlId());
            EIDASAuthnResponse authnResponse = new EIDASAuthnResponse();
            authnResponse.setPersonalAttributeList(authData.getPersonalAttributeList());
            boolean generateSignedAssertion = Boolean.parseBoolean(serviceUtil.getConfigs()==null?null:serviceUtil.getConfigs().getProperty(EIDASParameters.RESPONSE_SIGN_ASSERTION.toString()));
            serviceUtil.setMetadatUrlToAuthnResponse(getServiceMetadataUrl(), authnResponse);
            // TODO : Question : Is that true
            if(authData.getEidasLoA()==null) {
                authnResponse.setAssuranceLevel(serviceUtil.getProperty(EIDASValues.EIDAS_SERVICE_LOA.toString()));
            }else{
                authnResponse.setAssuranceLevel(authData.getEidasLoA());
            }

            // Generate SAMLResponse.
            authnResponse = engine.generateEIDASAuthnResponse(authData, authnResponse,
                            ipUserAddress, false, generateSignedAssertion);

            // Audit
            final String message = EIDASValues.SUCCESS.toString() + EIDASValues.EID_SEPARATOR.toString() + EIDASValues.CITIZEN_CONSENT_LOG.toString();
            authnResponse.setInResponseTo(authData.getSamlId());
            prepareRespLoggerBean(authnResponse, message);
            this.saveLog(AUSERVICESAML.LOGGER_COM_RESP);

            return authnResponse.getTokenSaml();
        } catch (final EIDASSAMLEngineException e) {
            LOGGER.info("BUSINESS EXCEPTION : Error generating SAMLToken", e.getMessage());
            LOGGER.debug("BUSINESS EXCEPTION : Error generating SAMLToken", e);
            EidasNodeErrorUtil.processSAMLEngineException(e, LOGGER,EIDASErrors.COLLEAGUE_REQ_INVALID_SAML);
            throw new InternalErrorEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.SERVICE_SAML_RESPONSE.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.SERVICE_SAML_RESPONSE.errorMessage()), e);
        }finally {
            if(engine!=null) {
                getSamlEngineFactory().releaseEngine(engine);
            }
        }
    }
    private String resolveErrorMessage(String errorCode, String statusCode, String errorId){
        String errorMsg;
        try {
            if (StringUtils.isNumeric(errorCode)) {
                errorMsg =
                        messageSource.getMessage(errorId, new Object[]{errorCode},
                                Locale.getDefault());
            } else {
                errorMsg =
                        messageSource.getMessage(errorId, new Object[]{statusCode},
                                Locale.getDefault());
            }
        }catch(NoSuchMessageException nme){//NOSONAR
            errorMsg=errorCode+" - "+errorId;
        }
        return errorMsg;
    }
    /**
     * {@inheritDoc}
     */
    public byte[] generateErrorAuthenticationResponse(
            final EIDASAuthnRequest authData, final String code, final String subCode,
            final String errorMessage, final String ipUserAddress,
            final boolean isAuditable) {
        EIDASSAMLEngine engine = null;
        try {
            engine = getSamlEngineFactory().getEngine(getSamlEngineInstanceName(), getServiceUtil() == null ? null : getServiceUtil()
                    .getConfigs());
            // create SAML token

            EIDASAuthnResponse eidasAuthnResponseError = new EIDASAuthnResponse();
            eidasAuthnResponseError.setStatusCode(code);
            eidasAuthnResponseError.setSubStatusCode(subCode);

            final String errorCode = EIDASUtil.getEidasErrorCode(errorMessage);
            String errorMsg = EIDASUtil.getEidasErrorMessage(errorMessage);
            LOGGER.debug(LoggingMarkerMDC.SAML_EXCHANGE, "ProxyService - Generating ERROR SAML Response to request with ID {}, error is {} {}",
                    authData.getSamlId(), errorCode, errorMsg);
            eidasAuthnResponseError.setMessage(resolveErrorMessage(errorCode, code, errorMsg));
            serviceUtil.setMetadatUrlToAuthnResponse(getServiceMetadataUrl(), eidasAuthnResponseError);

            if(authData.getIssuer()!=null){
                engine.setRequestIssuer(authData.getIssuer());
            }
            eidasAuthnResponseError.setAssuranceLevel(serviceUtil.getProperty(EIDASValues.EIDAS_SERVICE_LOA.toString()));


            eidasAuthnResponseError = engine.generateEIDASAuthnResponseFail(authData, eidasAuthnResponseError, ipUserAddress, false);

            if (isAuditable) {
                // Fix a SAML Engine bug: Don't set InResponseTo
                eidasAuthnResponseError.setInResponseTo(authData.getSamlId());
                prepareRespLoggerBean(eidasAuthnResponseError, errorMsg);
                this.saveLog(AUSERVICESAML.LOGGER_COM_RESP);
            }

            return eidasAuthnResponseError.getTokenSaml();
        } catch (final EIDASSAMLEngineException e) {
            LOGGER.info("BUSINESS EXCEPTION : Error generating SAMLToken", e.getMessage());
            LOGGER.debug("BUSINESS EXCEPTION : Error generating SAMLToken", e);
            EidasNodeErrorUtil.processSAMLEngineException(e, LOGGER, EIDASErrors.COLLEAGUE_REQ_INVALID_SAML);
            throw new InternalErrorEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_ERROR_CREATE_SAML
                            .errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_ERROR_CREATE_SAML
                            .errorMessage()), e);
        }finally {
            if(engine!=null) {
                getSamlEngineFactory().releaseEngine(engine);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public byte[] getSAMLToken(final String samlToken) {

        if (samlToken == null) {
            LOGGER.info("BUSINESS EXCEPTION : SAML Token is null");
            throw new InvalidParameterEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()));
        }
        return EIDASUtil.decodeSAMLToken(samlToken);
    }

    /**
     * {@inheritDoc}
     */
    public EIDASAuthnRequest processAuthenticationRequest(final byte[] samlObj,
                                                          final IEIDASSession session, final String ipUserAddress) {
        EIDASSAMLEngine engine = null;
        try {
            LOGGER.trace("Validating the SAML token");
            // validates SAML Token
            engine = getSamlEngineFactory().getEngine(getSamlEngineInstanceName(), getServiceUtil()==null?null:getServiceUtil().getConfigs());
            final EIDASAuthnRequest authnRequest = engine.validateEIDASAuthnRequest(samlObj);

            //the validation which follow should be able to generate fail responses if necessary
            session.put(EIDASParameters.AUTH_REQUEST.toString(), authnRequest);

            LOGGER.info(LoggingMarkerMDC.SAML_EXCHANGE, "ProxyService - Processing SAML Request with ID {}", authnRequest.getSamlId());
            if(StringUtils.isEmpty(authnRequest.getAssertionConsumerServiceURL())){
                //retrieve it from the metadata
                authnRequest.setAssertionConsumerServiceURL(MetadataUtil.getAssertionUrlFromMetadata(metadataProcessor, engine, authnRequest));
            }
            LOGGER.debug("Setting error redirect url:" + authnRequest.getAssertionConsumerServiceURL());
            session.put(EIDASParameters.ERROR_REDIRECT_URL.toString(), authnRequest.getAssertionConsumerServiceURL());

            if (StringUtils.isEmpty(authnRequest.getCitizenCountryCode())) {
                authnRequest.setCitizenCountryCode(countryCode);
            }

            checkCountryCode(authnRequest, ipUserAddress);
            checkQaa(authnRequest, ipUserAddress);

            // Validates Personal Attribute List
            EIDASUtil.validateParameter(AUSERVICESAML.class.getCanonicalName(),
                    EIDASParameters.ATTRIBUTE_LIST.toString(), authnRequest
                    .getPersonalAttributeList().toString(),
                    EIDASErrors.COLLEAGUE_REQ_ATTR_NULL);
            final Boolean validateBindingConfig = Boolean.valueOf(serviceUtil.getProperty(EIDASParameters.VALIDATE_BINDING.toString()));
            LOGGER.info("message Format name " + authnRequest.getMessageFormatName());
            // Validates Connector's Redirect URL
            if (serviceUtil.isEIDAS10(authnRequest.getMessageFormatName())){
                final String maxLoAConfig=serviceUtil.getProperty(EIDASValues.EIDAS_SERVICE_LOA.toString());

                LOGGER.debug("Checking validation for eidas 1,0 - max loa configured {}, validate binding config {}", maxLoAConfig, validateBindingConfig);
                if(eu.eidas.node.auth.service.protocol_eidas1_0.AUSERVICESAMLUtil.
                                eidasValidationSentSamlAuthticationError(engine, authnRequest, session, metadataProcessor, validateBindingConfig, maxLoAConfig)){
                    LOGGER.info("BUSINESS EXCEPTION : Invalid Level of Assurance value");
                    final String errorMsgCons = EIDASErrors.COLLEAGUE_REQ_INVALID_LOA.errorMessage();
                    final String errorCodeCons = EIDASErrors.COLLEAGUE_REQ_INVALID_LOA.errorCode();

                    final byte[] samlTokenFail =
                            generateErrorAuthenticationResponse(authnRequest,
                                    EIDASStatusCode.REQUESTER_URI.toString(),
                                    null,
                                    EIDASUtil.getConfig(errorMsgCons), ipUserAddress, true);

                    throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail),
                            EIDASUtil.getConfig(errorCodeCons), EIDASUtil.getConfig(errorMsgCons));
                }

                session.put(EIDASParameters.ERROR_REDIRECT_URL.toString(),authnRequest.getAssertionConsumerServiceURL());
            }else {
                // Non eidas Messages need to be supported
                if (serviceUtil.isEidasMessageSupportedOnly()){
                    final String errorCode = EIDASUtil.getConfig(EIDASErrors.MESSAGE_FORMAT_UNSUPPORTED.errorCode());
                    final String errorMessage = EIDASUtil.getConfig(EIDASErrors.MESSAGE_FORMAT_UNSUPPORTED.errorMessage());
                    final byte[] samlTokenFail =
                            generateErrorAuthenticationResponse(authnRequest,
                                    errorCode,
                                    null,
                                    errorMessage, ipUserAddress, true);

                    throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail), errorCode, errorMessage);
                }
                if(validateBindingConfig) {
                    EidasNodeValidationUtil.validateBinding(authnRequest, (String) session.get(EIDASParameters.HTTP_METHOD.toString()), EIDASErrors.COLLEAGUE_REQ_INVALID_SAML);
                }
                EIDASUtil.validateParameter(AUSERVICESAML.class.getCanonicalName(),
                        EIDASParameters.EIDAS_CONNECTOR_REDIRECT_URL.toString(),
                        authnRequest.getAssertionConsumerServiceURL(),
                        EIDASErrors.COLLEAGUE_REQ_INVALID_REDIRECT);
            }

            // Checking for antiReplay
            checkAntiReplay(samlObj, authnRequest);
            // Logging
            LOGGER.trace("Eidas Audit");
            prepareReqLoggerBean(samlObj, authnRequest);
            this.saveLog(AUSERVICESAML.LOGGER_COM_REQ);

            return authnRequest;
        }catch (final EIDASSAMLEngineException e) {
            LOGGER.info("BUSINESS EXCEPTION : Error validating SAMLToken", e);
            if(EIDASErrors.INVALID_LOA_VALUE.errorCode().equals(e.getErrorCode())){
                throw new InternalErrorEIDASException(
                        EIDASUtil.getConfig(EIDASErrors.INVALID_LOA_VALUE.errorCode()),
                        EIDASUtil.getConfig(EIDASErrors.INVALID_LOA_VALUE.errorMessage()),e);
            }
            EidasNodeErrorUtil.processSAMLEngineException(e, LOGGER, EIDASErrors.COLLEAGUE_REQ_INVALID_SAML);
            throw new InternalErrorEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()),
                    e);

        }finally {
            if(engine!=null) {
                getSamlEngineFactory().releaseEngine(engine);
            }
        }
    }

    private void checkAntiReplay(final byte[] samlObj,final EIDASAuthnRequest authnRequest){
        if (!serviceUtil.checkNotPresentInCache(authnRequest.getSamlId(), authnRequest.getCitizenCountryCode())) {
            LOGGER.trace("Eidas Audit");
            prepareReqLoggerBean(samlObj, authnRequest);
            this.saveLog(AUSERVICESAML.LOGGER_COM_REQ);
            throw new SecurityEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML.errorMessage()));
        }

    }
    private void checkQaa(final EIDASAuthnRequest authnRequest, final String ipUserAddress){
        LOGGER.trace("Validating QAA level");
        if (authnRequest.getQaa() > getMaxQAAlevel()) {
            LOGGER.info("BUSINESS EXCEPTION : Invalid QAA Level");
            final String errorMsgCons =
                    EIDASErrors.COLLEAGUE_REQ_INVALID_QAA.errorMessage();
            final String errorCodeCons =
                    EIDASErrors.COLLEAGUE_REQ_INVALID_QAA.errorCode();

            final byte[] samlTokenFail =
                    generateErrorAuthenticationResponse(authnRequest,
                            EIDASStatusCode.REQUESTER_URI.toString(),
                            EIDASSubStatusCode.QAA_NOT_SUPPORTED.toString(),
                            EIDASUtil.getConfig(errorMsgCons), ipUserAddress, true);

            throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail),
                    EIDASUtil.getConfig(errorCodeCons), EIDASUtil.getConfig(errorMsgCons));
        }

    }

    private void checkCountryCode(final EIDASAuthnRequest authnRequest, final String ipUserAddress ){
        // validates if the current countryCode is the same as the countryCode
        // in the request
        final String samlCountryCode =authnRequest.getCitizenCountryCode()==null?null:
                authnRequest.getCitizenCountryCode()
                        .replace(EIDASValues.EIDAS_SERVICE_SUFFIX.toString(),
                                EIDASValues.EMPTY_STRING.toString());
        if (StringUtils.isEmpty(countryCode)
                || !countryCode.equals(samlCountryCode)) {

            LOGGER.info("BUSINESS EXCEPTION : Invalid Country Code " + authnRequest.getCitizenCountryCode());
            final byte[] samlTokenFail =
                    generateErrorAuthenticationResponse(authnRequest,
                            EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE
                                    .errorCode()), null,
                            EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE
                                    .errorMessage()), ipUserAddress, true);

            throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail),
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE
                            .errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE.errorMessage()));
        }

    }
    /**
     * {@inheritDoc}
     */
    public void checkAttributeValues(final EIDASAuthnRequest authData,
                                     final String ipUserAddress) {

        if (!specificNode.checkAttributeValues(authData)) {
            final byte[] error =
                    generateErrorAuthenticationResponse(
                            authData,
                            EIDASUtil.getConfig(EIDASErrors.ATTR_VALUE_VERIFICATION.errorCode()),
                            EIDASStatusCode.RESPONDER_URI.toString(),
                            EIDASUtil.getConfig(EIDASErrors.ATTR_VALUE_VERIFICATION.errorMessage()),
                            ipUserAddress, true);

            throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(error),
                    EIDASUtil.getConfig(EIDASErrors.ATTR_VALUE_VERIFICATION.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.ATTR_VALUE_VERIFICATION.errorMessage()));
        }
    }

    /**
     * Sets all the fields to audit the request.
     *
     * @param samlObj      The SAML token byte[].
     * @param authnRequest The Authentication Request object.
     * @see EIDASAuthnRequest
     */
    private void prepareReqLoggerBean(final byte[] samlObj,
                                      final EIDASAuthnRequest authnRequest) {
        final String hashClassName=serviceUtil.getProperty(EIDASParameters.HASH_DIGEST_CLASS.toString());
        final byte[] tokenHash = EIDASUtil.hashPersonalToken(samlObj, hashClassName);
        loggerBean.setTimestamp(DateUtil.currentTimeStamp().toString());
        loggerBean.setOpType(EIDASValues.EIDAS_SERVICE_REQUEST.toString());
        loggerBean.setOrigin(authnRequest.getAssertionConsumerServiceURL());
        loggerBean.setDestination(authnRequest.getDestination());
        loggerBean.setSpApplication(authnRequest.getSpApplication());
        loggerBean.setProviderName(authnRequest.getProviderName());
        loggerBean.setCountry(authnRequest.getSpCountry());
        loggerBean.setQaaLevel(authnRequest.getQaa());
        loggerBean.setSamlHash(tokenHash);
        loggerBean.setMsgId(authnRequest.getSamlId());
    }

    /**
     * Sets all the fields to the audit the response.
     *
     * @param message       The Saml response message.
     * @param authnResponse The Authentication Response object.
     * @see EIDASAuthnRequest
     */
    protected void prepareRespLoggerBean(final EIDASAuthnResponse authnResponse,
                                         final String message) {
        final String hashClassName=serviceUtil.getProperty(EIDASParameters.HASH_DIGEST_CLASS.toString());
        final byte[] tokenHash =
                EIDASUtil.hashPersonalToken(authnResponse.getTokenSaml(), hashClassName);
        loggerBean.setTimestamp(DateUtil.currentTimeStamp().toString());
        loggerBean.setOpType(EIDASValues.EIDAS_SERVICE_RESPONSE.toString());
        loggerBean.setInResponseTo(authnResponse.getInResponseTo());
        loggerBean.setMessage(message);
        loggerBean.setSamlHash(tokenHash);
        loggerBean.setMsgId(authnResponse.getSamlId());
    }

    /**
     * Logs the transaction with the Audit log.
     *
     * @param logger The Audit Logger.
     */
    public void saveLog(final Logger logger) {
        logger.info(LoggingMarkerMDC.SAML_EXCHANGE, loggerBean.toString());
    }

    /**
     * Setter for loggerBean.
     *
     * @param nLoggerBean The new loggerBean value.
     * @see IEIDASLogger
     */
    public void setLoggerBean(final IEIDASLogger nLoggerBean) {
        this.loggerBean = nLoggerBean;
    }

    /**
     * Getter for loggerBean.
     *
     * @return The loggerBean value.
     * @see IEIDASLogger
     */
    public IEIDASLogger getLoggerBean() {
        return loggerBean;
    }

    /**
     * Getter for countryCode.
     *
     * @return The countryCode value.
     */
    public String getCountryCode() {
        return countryCode;
    }

    /**
     * Setter for countryCode.
     *
     * @param code The countryCode to set.
     */
    public void setCountryCode(final String code) {
        this.countryCode = code;
    }

    /**
     * Getter for maxQAAlevel.
     *
     * @return The maxQAAlevel value.
     */
    public int getMaxQAAlevel() {
        if (maxQAAlevel < this.getMinQAA() || maxQAAlevel > this.getMaxQAA()) {
            throw new InvalidParameterEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.QAALEVEL.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.QAALEVEL.errorMessage()));
        }
        return maxQAAlevel;
    }

    /**
     * Getter for minQAA.
     *
     * @return The minQAA value.
     */
    public int getMinQAA() {
        return minQAA;
    }

    /**
     * Setter for minQAA.
     *
     * @param nMinQAA The new minQAA value.
     */
    public void setMinQAA(final int nMinQAA) {
        this.minQAA = nMinQAA;
    }

    /**
     * Getter for maxQAA.
     *
     * @return The maxQAA value.
     */
    public int getMaxQAA() {
        return maxQAA;
    }

    /**
     * Setter for maxQAA Level allowed.
     *
     * @param nMaxQAA The new maxQAA value.
     */
    public void setMaxQAA(final int nMaxQAA) {
        this.maxQAA = nMaxQAA;
    }

    /**
     * Setter for maxQAAlevel.
     *
     * @param nMaxQAAlevel The new maxQAAlevel value.
     */
    public void setMaxQAAlevel(final int nMaxQAAlevel) {
        this.maxQAAlevel = nMaxQAAlevel;
    }

    /**
     * Getter for specificNode.
     *
     * @return The specificNode value.
     * @see ITranslatorService
     */
    public ITranslatorService getSpecificNode() {
        return specificNode;
    }

    /**
     * Setter for specificNode.
     *
     * @param specificNode The new specificNode value.
     * @see ITranslatorService
     */
    public void setSpecificNode(final ITranslatorService specificNode) {
        this.specificNode = specificNode;
    }

    /**
     * Setter for messageSource.
     *
     * @param nMessageSource The new messageSource value.
     * @see MessageSource
     */
    public void setMessageSource(final MessageSource nMessageSource) {
        this.messageSource = nMessageSource;
    }

    public AUSERVICEUtil getServiceUtil() {
        return serviceUtil;
    }
    public void setServiceUtil(AUSERVICEUtil serviceUtil) {
        this.serviceUtil = serviceUtil;
    }

    public String getServiceMetadataUrl() {
        return serviceMetadataUrl;
    }

    public void setServiceMetadataUrl(String serviceMetadataUrl) {
        this.serviceMetadataUrl = serviceMetadataUrl;
    }

    public void setMetadataProcessor(MetadataProcessorI metadataProcessor) {
        this.metadataProcessor = metadataProcessor;
    }

    public String getServiceRequesterMetadataUrl() {
        return serviceRequesterMetadataUrl;
    }

    public void setServiceRequesterMetadataUrl(String serviceRequesterMetadataUrl) {
        this.serviceRequesterMetadataUrl = serviceRequesterMetadataUrl;
    }
}
