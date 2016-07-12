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
package eu.stork.peps.auth.cpeps;

import eu.stork.peps.auth.commons.exceptions.*;
import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.init.StorkSAMLEngineFactory;
import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.specific.ITranslatorService;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.peps.logging.LoggingMarkerMDC;
import eu.stork.peps.utils.PEPSErrorUtil;
import eu.stork.peps.utils.PEPSValidationUtil;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;

import java.util.Locale;

/**
 * This class is used by {@link AUCPEPS} to get, process and generate SAML
 * Tokens. Also, it checks attribute values and mandatory attributes.
 *
 * @see ICPEPSSAMLService
 */
public class AUCPEPSSAML implements ICPEPSSAMLService {

    /**
     * S-PEPS's Util class.
     */
    protected AUCPEPSUtil cpepsUtil;

    /**
     * Logger object.
     */
    protected static final Logger LOGGER = LoggerFactory.getLogger(AUCPEPSSAML.class
            .getName());

    /**
     * Request Stork logging.
     */
    private static final Logger LOGGER_COM_REQ = LoggerFactory
            .getLogger(PEPSValues.STORK_PACKAGE_REQUEST_LOGGER_VALUE.toString() + "."
                    + AUCPEPS.class.getSimpleName());

    /**
     * Response Stork logging.
     */
    protected static final Logger LOGGER_COM_RESP = LoggerFactory
            .getLogger(PEPSValues.STORK_PACKAGE_RESPONSE_LOGGER_VALUE.toString() + "."
                    + AUCPEPS.class.getSimpleName());

    /**
     * Logger bean.
     */
    private IStorkLogger loggerBean;

    /**
     * Specific interface.
     */
    private ITranslatorService specificPeps;

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
     * Country Code of this C-PEPS.
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
     * Max QAA Level that this C-PEPS can authenticate.
     */
    private int maxQAAlevel;

    /**
     * Resource bundle to get error messages.
     */
    private MessageSource messageSource;

    private long skewTime;

    private StorkSAMLEngineFactory storkSAMLEngineFactory;

    private String cpepsMetadataUrl;
    private String cpepsRequesterMetadataUrl;
    private MetadataProcessorI metadataProcessor;

    public long getSkewTime() {
        return skewTime;
    }

    public void setSkewTime(long skewTime) {
        this.skewTime = skewTime;
    }

    public StorkSAMLEngineFactory getStorkSAMLEngineFactory() {
        return storkSAMLEngineFactory;
    }

    public void setStorkSAMLEngineFactory(StorkSAMLEngineFactory storkSAMLEngineFactory) {
        this.storkSAMLEngineFactory = storkSAMLEngineFactory;
    }

    /**
     * {@inheritDoc}
     */
    public void checkMandatoryAttributes(final STORKAuthnRequest authnData,
                                         final String ipUserAddress) {
        if (authnData==null || !AttributeUtil.checkMandatoryAttributes(authnData.getPersonalAttributeList())) {
            LOGGER.info("BUSINESS EXCEPTION : Mandatory attribute is missing!");
            final byte[] error =
                    generateErrorAuthenticationResponse(authnData, PEPSUtil
                            .getConfig(PEPSErrors.ATT_VERIFICATION_MANDATORY.errorCode()),
                            STORKSubStatusCode.REQUEST_DENIED_URI.toString(), PEPSUtil
                            .getConfig(PEPSErrors.ATT_VERIFICATION_MANDATORY.errorMessage()),
                            ipUserAddress, true);
            if (LOGGER.isInfoEnabled()){
                LOGGER.info("Missing attributes: " + AttributeUtil.getMissingMandatoryAttributes(authnData.getPersonalAttributeList()));
            }
            throw new CPEPSException(
                    PEPSUtil.encodeSAMLToken(error),
                    PEPSUtil.getConfig(PEPSErrors.ATT_VERIFICATION_MANDATORY.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.ATT_VERIFICATION_MANDATORY.errorMessage()));
        }
    }

    /**
     * {@inheritDoc}
     */
    public byte[] generateAuthenticationResponse(
            final STORKAuthnRequest authData, final String ipUserAddress,
            final boolean isConsent) {
        STORKSAMLEngine engine=null;
        try {
             engine= getStorkSAMLEngineFactory().getEngine(getSamlEngineInstanceName(), getCpepsUtil() == null ? null : getCpepsUtil()
                     .getConfigs());
            engine.setRequestIssuer(authData.getIssuer());
            LOGGER.trace("check assertion consumer url of the partner requesting this");
            LOGGER.info(LoggingMarkerMDC.SAML_EXCHANGE, "CPEPS - Generating SAML Response to request with ID {}", authData.getSamlId());
            STORKAuthnResponse authnResponse = new STORKAuthnResponse();
            authnResponse.setPersonalAttributeList(authData.getPersonalAttributeList());
            boolean generateSignedAssertion = Boolean.parseBoolean(cpepsUtil.getConfigs()==null?null:cpepsUtil.getConfigs().getProperty(PEPSParameters.RESPONSE_SIGN_ASSERTION.toString()));
            cpepsUtil.setMetadatUrlToAuthnResponse(getCpepsMetadataUrl(), authnResponse);
            // TODO : Question : Is that true
            authnResponse.setAssuranceLevel(cpepsUtil.getProperty(PEPSValues.EIDAS_SERVICE_LOA.toString()));
            authData.setEidasLoA(cpepsUtil.getProperty(PEPSValues.EIDAS_SERVICE_LOA.toString()));

            // Generate SAMLResponse.
            authnResponse = engine.generateSTORKAuthnResponse(authData, authnResponse,
                            ipUserAddress, false, generateSignedAssertion);

            // Stork Audit
            final String message = PEPSValues.SUCCESS.toString() + PEPSValues.EID_SEPARATOR.toString() + PEPSValues.CITIZEN_CONSENT_LOG.toString();
            authnResponse.setInResponseTo(authData.getSamlId());
            prepareRespLoggerBean(authnResponse, message);
            this.saveLog(AUCPEPSSAML.LOGGER_COM_RESP);

            return authnResponse.getTokenSaml();
        } catch (final STORKSAMLEngineException e) {
            LOGGER.info("BUSINESS EXCEPTION : Error generating SAMLToken", e.getMessage());
            LOGGER.debug("BUSINESS EXCEPTION : Error generating SAMLToken", e);
            PEPSErrorUtil.processSAMLEngineException(e, LOGGER,PEPSErrors.COLLEAGUE_REQ_INVALID_SAML);
            throw new InternalErrorPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.CPEPS_SAML_RESPONSE.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.CPEPS_SAML_RESPONSE.errorMessage()), e);
        }finally {
            if(engine!=null) {
                getStorkSAMLEngineFactory().releaseEngine(engine);
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
            final STORKAuthnRequest authData, final String code, final String subCode,
            final String errorMessage, final String ipUserAddress,
            final boolean isAuditable) {
        STORKSAMLEngine engine = null;
        try {
            engine = getStorkSAMLEngineFactory().getEngine(getSamlEngineInstanceName(), getCpepsUtil() == null ? null : getCpepsUtil()
                    .getConfigs());
            // create SAML token

            STORKAuthnResponse storkAuthnResponseError = new STORKAuthnResponse();
            storkAuthnResponseError.setStatusCode(code);
            storkAuthnResponseError.setSubStatusCode(subCode);

            final String errorCode = PEPSUtil.getStorkErrorCode(errorMessage);
            String errorMsg = PEPSUtil.getStorkErrorMessage(errorMessage);
            LOGGER.debug(LoggingMarkerMDC.SAML_EXCHANGE, "CPEPS - Generating ERROR SAML Response to request with ID {}, error is {} {}",
                    authData.getSamlId(), errorCode, errorMsg);
            storkAuthnResponseError.setMessage(resolveErrorMessage(errorCode, code, errorMsg));
            cpepsUtil.setMetadatUrlToAuthnResponse(getCpepsMetadataUrl(), storkAuthnResponseError);

            if(authData.getIssuer()!=null){
                engine.setRequestIssuer(authData.getIssuer());
            }
            storkAuthnResponseError.setAssuranceLevel(cpepsUtil.getProperty(PEPSValues.EIDAS_SERVICE_LOA.toString()));


            storkAuthnResponseError = engine.generateSTORKAuthnResponseFail(authData, storkAuthnResponseError, ipUserAddress, false);

            if (isAuditable) {
                // Fix a SAML Engine bug: Don't set InResponseTo
                storkAuthnResponseError.setInResponseTo(authData.getSamlId());
                prepareRespLoggerBean(storkAuthnResponseError, errorMsg);
                this.saveLog(AUCPEPSSAML.LOGGER_COM_RESP);
            }

            return storkAuthnResponseError.getTokenSaml();
        } catch (final STORKSAMLEngineException e) {
            LOGGER.info("BUSINESS EXCEPTION : Error generating SAMLToken", e.getMessage());
            LOGGER.debug("BUSINESS EXCEPTION : Error generating SAMLToken", e);
            PEPSErrorUtil.processSAMLEngineException(e, LOGGER, PEPSErrors.COLLEAGUE_REQ_INVALID_SAML);
            throw new InternalErrorPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_ERROR_CREATE_SAML
                            .errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_ERROR_CREATE_SAML
                            .errorMessage()), e);
        }finally {
            if(engine!=null) {
                getStorkSAMLEngineFactory().releaseEngine(engine);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public byte[] getSAMLToken(final String samlToken) {

        if (samlToken == null) {
            LOGGER.info("BUSINESS EXCEPTION : SAML Token is null");
            throw new InvalidParameterPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()));
        }
        return PEPSUtil.decodeSAMLToken(samlToken);
    }

    /**
     * {@inheritDoc}
     */
    public STORKAuthnRequest processAuthenticationRequest(final byte[] samlObj,
                                                          final IStorkSession session, final String ipUserAddress) {
        STORKSAMLEngine engine = null;
        try {
            LOGGER.trace("Validating the SAML token");
            // validates SAML Token
            engine = getStorkSAMLEngineFactory().getEngine(getSamlEngineInstanceName(), getCpepsUtil()==null?null:getCpepsUtil().getConfigs());
            final STORKAuthnRequest authnRequest = engine.validateSTORKAuthnRequest(samlObj);

            LOGGER.info(LoggingMarkerMDC.SAML_EXCHANGE, "CPEPS - Processing SAML Request with ID {}", authnRequest.getSamlId());
            if(StringUtils.isEmpty(authnRequest.getAssertionConsumerServiceURL())){
                //retrieve it from the metadata
                setAssertionUrlFromMetadata(engine, authnRequest);
            }
            LOGGER.debug("Setting error redirect url:" + authnRequest.getAssertionConsumerServiceURL());
            session.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), authnRequest.getAssertionConsumerServiceURL());

            if (StringUtils.isEmpty(authnRequest.getCitizenCountryCode())) {
                authnRequest.setCitizenCountryCode(countryCode);
            }

            checkCountryCode(authnRequest, ipUserAddress);
            checkQaa(authnRequest, ipUserAddress);

            // Validates Personal Attribute List
            PEPSUtil.validateParameter(AUCPEPSSAML.class.getCanonicalName(),
                    PEPSParameters.ATTRIBUTE_LIST.toString(), authnRequest
                            .getPersonalAttributeList().toString(),
                    PEPSErrors.COLLEAGUE_REQ_ATTR_NULL);
            final Boolean validateBindingConfig = Boolean.valueOf(cpepsUtil.getProperty(PEPSParameters.VALIDATE_BINDING.toString()));
            LOGGER.info("message Format name " + authnRequest.getMessageFormatName());
            // Validates S-PEPS Redirect URL
            if (cpepsUtil.isEIDAS10(authnRequest.getMessageFormatName())){
                final String maxLoAConfig=cpepsUtil.getProperty(PEPSValues.EIDAS_SERVICE_LOA.toString());

                LOGGER.debug("Checking validation for eidas 1,0 - max loa configured {}, validate binding config {}", maxLoAConfig, validateBindingConfig);
                if(eu.stork.peps.auth.cpeps.protocol_eidas1_0.AUCPEPSSAMLUtil.
                                eidasValidationSentSamlAuthticationError(engine, authnRequest, session, metadataProcessor, validateBindingConfig, maxLoAConfig)){
                    LOGGER.info("BUSINESS EXCEPTION : Invalid Level of Assurance value");
                    final String errorMsgCons = PEPSErrors.COLLEAGUE_REQ_INVALID_LOA.errorMessage();
                    final String errorCodeCons = PEPSErrors.COLLEAGUE_REQ_INVALID_LOA.errorCode();

                    final byte[] samlTokenFail =
                            generateErrorAuthenticationResponse(authnRequest,
                                    STORKStatusCode.REQUESTER_URI.toString(),
                                    null,
                                    PEPSUtil.getConfig(errorMsgCons), ipUserAddress, true);

                    throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail),
                            PEPSUtil.getConfig(errorCodeCons), PEPSUtil.getConfig(errorMsgCons));
                }

                session.put(PEPSParameters.ERROR_REDIRECT_URL.toString(),authnRequest.getAssertionConsumerServiceURL());
            }else {
                // Non eidas Messages need to be supported
                if (cpepsUtil.isEidasMessageSupportedOnly()){
                final String errorCode = PEPSUtil.getConfig(PEPSErrors.MESSAGF_FORMAT_UNSUPPORTED.errorCode());
                final String errorMessage = PEPSUtil.getConfig(PEPSErrors.MESSAGF_FORMAT_UNSUPPORTED.errorMessage());
                final byte[] samlTokenFail =
                        generateErrorAuthenticationResponse(authnRequest,
                                errorCode,
                                null,
                                errorMessage, ipUserAddress, true);

                throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail), errorCode, errorMessage);
                }
                if(validateBindingConfig) {
                    PEPSValidationUtil.validateBinding(authnRequest, (String) session.get(PEPSParameters.HTTP_METHOD.toString()), PEPSErrors.COLLEAGUE_REQ_INVALID_SAML);
                }
                PEPSUtil.validateParameter(AUCPEPSSAML.class.getCanonicalName(),
                        PEPSParameters.SPEPS_REDIRECT_URL.toString(),
                        authnRequest.getAssertionConsumerServiceURL(),
                        PEPSErrors.COLLEAGUE_REQ_INVALID_REDIRECT);
            }

            // Checking for antiReplay
            checkAntiReplay(samlObj, authnRequest);

            // Stork Logging
            LOGGER.trace("Stork Audit");
            prepareReqLoggerBean(samlObj, authnRequest);
            this.saveLog(AUCPEPSSAML.LOGGER_COM_REQ);

            return authnRequest;
        } catch (final STORKSAMLEngineException e) {
            LOGGER.info("BUSINESS EXCEPTION : Error validating SAMLToken", e);
            PEPSErrorUtil.processSAMLEngineException(e, LOGGER, PEPSErrors.COLLEAGUE_REQ_INVALID_SAML);
            throw new InternalErrorPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()),
                    e);

        }finally {
            if(engine!=null) {
                getStorkSAMLEngineFactory().releaseEngine(engine);
            }
        }
    }
    private void setAssertionUrlFromMetadata(final STORKSAMLEngine engine, final STORKAuthnRequest authnRequest){
        if(!StringUtils.isEmpty(authnRequest.getIssuer())){
            try {
                metadataProcessor.checkValidMetadataSignature(authnRequest.getIssuer(), engine);
                SPSSODescriptor spDesc = metadataProcessor.getSPSSODescriptor(authnRequest.getIssuer());
                authnRequest.setAssertionConsumerServiceURL(getSPAssertionURL(spDesc));
            }catch(SAMLEngineException e){
                LOGGER.info("cannot retrieve assertion url from metadata at {} {}", authnRequest.getIssuer(), e);
            }

        }
    }


    private String getSPAssertionURL(SPSSODescriptor spDesc){
        if(spDesc==null || spDesc.getAssertionConsumerServices().isEmpty())
            return null;
        String assertionUrl=spDesc.getAssertionConsumerServices().get(0).getLocation();
        for(AssertionConsumerService acs:spDesc.getAssertionConsumerServices()){
            if(acs.isDefault()){
                assertionUrl=acs.getLocation();
            }
        }
        return assertionUrl;
    }

    private void checkAntiReplay(final byte[] samlObj,final STORKAuthnRequest authnRequest){
        if (!cpepsUtil.checkNotPresentInCache(authnRequest.getSamlId(), authnRequest.getCitizenCountryCode())) {
            LOGGER.trace("Stork Audit");
            prepareReqLoggerBean(samlObj, authnRequest);
            this.saveLog(AUCPEPSSAML.LOGGER_COM_REQ);
            throw new SecurityPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML.errorMessage()));
        }

    }
    private void checkQaa(final STORKAuthnRequest authnRequest, final String ipUserAddress){
        LOGGER.trace("Validating QAA level");
        if (authnRequest.getQaa() > getMaxQAAlevel()) {
            LOGGER.info("BUSINESS EXCEPTION : Invalid QAA Level");
            final String errorMsgCons =
                    PEPSErrors.COLLEAGUE_REQ_INVALID_QAA.errorMessage();
            final String errorCodeCons =
                    PEPSErrors.COLLEAGUE_REQ_INVALID_QAA.errorCode();

            final byte[] samlTokenFail =
                    generateErrorAuthenticationResponse(authnRequest,
                            STORKStatusCode.REQUESTER_URI.toString(),
                            STORKSubStatusCode.QAA_NOT_SUPPORTED.toString(),
                            PEPSUtil.getConfig(errorMsgCons), ipUserAddress, true);

            throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail),
                    PEPSUtil.getConfig(errorCodeCons), PEPSUtil.getConfig(errorMsgCons));
        }

    }

    private void checkCountryCode(final STORKAuthnRequest authnRequest, final String ipUserAddress ){
        // validates if the current countryCode is the same as the countryCode
        // in the request
        final String samlCountryCode =authnRequest.getCitizenCountryCode()==null?null:
                authnRequest.getCitizenCountryCode()
                        .replace(PEPSValues.PEPS_SUFFIX.toString(),
                                PEPSValues.EMPTY_STRING.toString());
        if (StringUtils.isEmpty(countryCode)
                || !countryCode.equals(samlCountryCode)) {

            LOGGER.info("BUSINESS EXCEPTION : Invalid Country Code " + authnRequest.getCitizenCountryCode());
            final byte[] samlTokenFail =
                    generateErrorAuthenticationResponse(authnRequest,
                            PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE
                                    .errorCode()), null,
                            PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE
                                    .errorMessage()), ipUserAddress, true);

            throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail),
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE
                            .errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_COUNTRYCODE.errorMessage()));
        }

    }
    /**
     * {@inheritDoc}
     */
    public void checkAttributeValues(final STORKAuthnRequest authData,
                                     final String ipUserAddress) {

        if (!specificPeps.checkAttributeValues(authData)) {
            final byte[] error =
                    generateErrorAuthenticationResponse(
                            authData,
                            PEPSUtil.getConfig(PEPSErrors.ATTR_VALUE_VERIFICATION.errorCode()),
                            STORKStatusCode.RESPONDER_URI.toString(),
                            PEPSUtil.getConfig(PEPSErrors.ATTR_VALUE_VERIFICATION.errorMessage()),
                            ipUserAddress, true);

            throw new CPEPSException(PEPSUtil.encodeSAMLToken(error),
                    PEPSUtil.getConfig(PEPSErrors.ATTR_VALUE_VERIFICATION.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.ATTR_VALUE_VERIFICATION.errorMessage()));
        }
    }

    /**
     * Sets all the fields to audit the request.
     *
     * @param samlObj      The SAML token byte[].
     * @param authnRequest The Authentication Request object.
     * @see STORKAuthnRequest
     */
    private void prepareReqLoggerBean(final byte[] samlObj,
                                      final STORKAuthnRequest authnRequest) {
        final String hashClassName=cpepsUtil.getProperty(PEPSParameters.PEPS_HASH_DIGEST_CLASS.toString());
        final byte[] tokenHash = PEPSUtil.hashPersonalToken(samlObj, hashClassName);
        loggerBean.setTimestamp(DateUtil.currentTimeStamp().toString());
        loggerBean.setOpType(PEPSValues.CPEPS_REQUEST.toString());
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
     * @see STORKAuthnRequest
     */
    protected void prepareRespLoggerBean(final STORKAuthnResponse authnResponse,
                                         final String message) {
        final String hashClassName=cpepsUtil.getProperty(PEPSParameters.PEPS_HASH_DIGEST_CLASS.toString());
        final byte[] tokenHash =
                PEPSUtil.hashPersonalToken(authnResponse.getTokenSaml(), hashClassName);
        loggerBean.setTimestamp(DateUtil.currentTimeStamp().toString());
        loggerBean.setOpType(PEPSValues.CPEPS_RESPONSE.toString());
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
     * @see IStorkLogger
     */
    public void setLoggerBean(final IStorkLogger nLoggerBean) {
        this.loggerBean = nLoggerBean;
    }

    /**
     * Getter for loggerBean.
     *
     * @return The loggerBean value.
     * @see IStorkLogger
     */
    public IStorkLogger getLoggerBean() {
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
            throw new InvalidParameterPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.QAALEVEL.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.QAALEVEL.errorMessage()));
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
     * Getter for specificPeps.
     *
     * @return The specificPeps value.
     * @see ITranslatorService
     */
    public ITranslatorService getSpecificPeps() {
        return specificPeps;
    }

    /**
     * Setter for specificPeps.
     *
     * @param nSpecificPeps The new specificPeps value.
     * @see ITranslatorService
     */
    public void setSpecificPeps(final ITranslatorService nSpecificPeps) {
        this.specificPeps = nSpecificPeps;
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

    public AUCPEPSUtil getCpepsUtil() {
        return cpepsUtil;
    }
    public void setCpepsUtil(AUCPEPSUtil cpepsUtil) {
        this.cpepsUtil = cpepsUtil;
    }

    public String getCpepsMetadataUrl() {
        return cpepsMetadataUrl;
    }

    public void setCpepsMetadataUrl(String cpepsMetadataUrl) {
        this.cpepsMetadataUrl = cpepsMetadataUrl;
    }

    public void setMetadataProcessor(MetadataProcessorI metadataProcessor) {
        this.metadataProcessor = metadataProcessor;
    }

    public String getCpepsRequesterMetadataUrl() {
        return cpepsRequesterMetadataUrl;
    }

    public void setCpepsRequesterMetadataUrl(String cpepsRequesterMetadataUrl) {
        this.cpepsRequesterMetadataUrl = cpepsRequesterMetadataUrl;
    }
}
