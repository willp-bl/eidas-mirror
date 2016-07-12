/*
 * Copyright (c) 2015 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.stork.peps.utils;

import eu.stork.peps.ApplicationContextProvider;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.*;
import eu.stork.peps.auth.cpeps.ICPEPSSAMLService;
import eu.stork.peps.auth.speps.ISPEPSSAMLService;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.peps.logging.LoggingMarkerMDC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.ResourceBundleMessageSource;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Locale;

/**
 * Utility class for preparing error saml response
 */
public class PEPSErrorUtil {

    public enum ErrorSource {
        SPEPS,
        CPEPS;
    }

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(PEPSErrorUtil.class.getName());

    private PEPSErrorUtil() {
    }

    /**
     * Method called by the PEPS exception handler to manage properly the exception occured
     *
     * @param request - the current http request
     * @param exc     - the exception for which the saml response is to be prepared
     *                <p/>
     *                side effect: exc's samlTokenFail is set to the saml response to return
     * @param source  Enum values defining C-PEPS/S-PEPS
     */
    public static void prepareSamlResponseFail(final HttpServletRequest request, AbstractPEPSException exc, ErrorSource source) {

        try {
            IStorkSession storkSession = (IStorkSession) request.getSession().getAttribute("scopedTarget.cPepsSession");
            if (storkSession == null || storkSession.isEmpty() || source == ErrorSource.SPEPS) {
                storkSession = (IStorkSession) request.getSession().getAttribute("scopedTarget.sPepsSession");
                prepareSamlResponseFailSpeps(request, exc, storkSession);
                return;
            }
            prepareSamlResponseFailCpeps(request, exc, storkSession);

        } catch (final Exception e) {
            LOG.info("ERROR : Error while trying to generate error SAMLToken", e.getMessage());
            LOG.debug("ERROR : Error while trying to generate error SAMLToken", e);
        }

    }

    /**
     * Method called for processing the SAML error message and specific error behaviour related
     * @param e the exception triggered
     * @param destLog the specific logger
     * @param redirectError the redirected error
     */
    public static void processSAMLEngineException(Exception e, Logger destLog, PEPSErrors redirectError) {
        // Special case for propagating the error in case of xxe
        String errorCode=null;
        if(e instanceof STORKSAMLEngineException){
            errorCode = ((STORKSAMLEngineException)e).getErrorCode();
        }else if(e instanceof SAMLEngineException){
            errorCode = ((SAMLEngineException)e).getErrorCode();
        }
        if(errorCode==null) {
            return;
        }
        if (PEPSErrors.DOC_TYPE_NOT_ALLOWED_CODE.toString().equals(errorCode)) {
            destLog.error(LoggingMarkerMDC.SECURITY_WARNING, "Error processing XML : XML entities processing DOCType not allowed, possible XXE attack ");
            throw new InternalErrorPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.DOC_TYPE_NOT_ALLOWED.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.DOC_TYPE_NOT_ALLOWED.errorMessage()), e);
        } else if (PEPSErrors.isErrorCode(errorCode)) {
            PEPSErrors err = PEPSErrors.fromCode(errorCode);
            String message = PEPSUtil.getConfig(err.errorMessage());
            if (ApplicationContextProvider.getApplicationContext() != null) {
                ResourceBundleMessageSource msgResource = (ResourceBundleMessageSource) ApplicationContextProvider.getApplicationContext().
                        getBean(PepsBeanNames.SYSADMIN_MESSAGE_RESOURCES.toString());
                final String errorMessage = msgResource.getMessage(message, new Object[]{
                        PEPSUtil.getConfig(err.errorCode())}, Locale.getDefault());
                destLog.info(errorMessage);
            }
            throw new InternalErrorPEPSException(
                    PEPSUtil.getConfig(redirectError.errorCode()),
                    PEPSUtil.getConfig(redirectError.errorMessage()), e);
        }
    }

    static Class[] samlEngineException={STORKSAMLEngineException.class, SAMLEngineException.class};
    private static boolean isSAMLEngineException(Throwable e){
        for(Class t:samlEngineException){
            if (t.isInstance(e)){
                return true;
            }
        }
        return false;
    }

    /**
     *
     * @param e
     * @return the base SAML engine exception
     */
    public static Exception getBaseSamlException(STORKSAMLEngineException e){
        Exception baseExc=e;
        Throwable currentException=e;
        while(true){
            if(currentException!=null && currentException.getCause()!=null && currentException!=currentException.getCause()){
                currentException=currentException.getCause();
                if(isSAMLEngineException(currentException)){
                    baseExc=(Exception)currentException;
                }
            }else {
                break;
            }
        }
        return baseExc;
    }

    private static String getErrorReportingUrl(final HttpServletRequest request, IStorkSession storkSession) {
        Object spUrl = request.getSession().getAttribute(PEPSParameters.SP_URL.toString());
        Object errorUrl = storkSession == null ? null : storkSession.get(PEPSParameters.ERROR_REDIRECT_URL.toString());
        Object errorInterceptorUrl = storkSession == null ? null : storkSession.get(PEPSParameters.ERROR_INTERCEPTOR_URL.toString());
        if (errorUrl != null) {
            spUrl = errorUrl;
        }
        if (errorInterceptorUrl != null) {
            request.setAttribute("redirectUrl", spUrl);
            spUrl = errorInterceptorUrl;
        }
        return spUrl == null ? null : spUrl.toString();
    }

    private static void prepareSamlResponseFailSpeps(final HttpServletRequest request, AbstractPEPSException exc, IStorkSession storkSession) {
        ISPEPSSAMLService spepsSamlService = ApplicationContextProvider.getApplicationContext().getBean(ISPEPSSAMLService.class);
        if (spepsSamlService == null) {
            return;
        }
        String spUrl = getErrorReportingUrl(request, storkSession);
        if (spUrl == null || !isErrorCodeAllowed(exc)) {
            LOG.info("ERROR : " + getPepsErrorMessage(exc, null));
            return;
        }
        byte[] samlToken = spepsSamlService.generateErrorAuthenticationResponse(getInResponseTo(request),
                getIssuer(request), spUrl.toString(),
                request.getRemoteAddr(), getSamlStatusCode(request),
                getSamlSubStatusCode(exc), exc.getErrorMessage());
        exc.setSamlTokenFail(PEPSUtil.encodeSAMLToken(samlToken));
        if (storkSession != null) {
            storkSession.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), spUrl);
        }

    }

    private static void prepareSamlResponseFailCpeps(final HttpServletRequest request, AbstractPEPSException exc, IStorkSession storkSession) {
        String spUrl = getErrorReportingUrl(request, storkSession);
        LOG.info("ERROR : " + exc.getErrorMessage());
        if (spUrl == null ) {
            return;
        }
        generateSamlResponse(request, exc, storkSession, spUrl);
    }

    private static void generateSamlResponse(final HttpServletRequest request, AbstractPEPSException exc, IStorkSession storkSession, String spUrl){
        ICPEPSSAMLService cpepsSamlService = ApplicationContextProvider.getApplicationContext().getBean(ICPEPSSAMLService.class);
        if (cpepsSamlService == null) {
            return;
        }
        if(exc.getUserErrorCode()!=null){
            exc.setErrorMessage("");
        }
        String samlSubStatusCode = getSamlSubStatusCode(exc);
        String errorMessage=exc.getErrorMessage();
        if(!isErrorCodeAllowed(exc)){
            if(exc.getUserErrorCode()!=null && isErrorCodeAllowed(exc.getUserErrorCode())){
                errorMessage = resolveMessage(exc.getUserErrorMessage(), exc.getUserErrorCode(), request.getLocale());
                samlSubStatusCode=getSamlSubStatusCode(exc.getUserErrorCode());
            }else {
                return;
            }
        }

        final STORKAuthnRequest authData = (STORKAuthnRequest) storkSession.get(PEPSParameters.AUTH_REQUEST.toString());
        if (authData == null) {
            LOG.info("ERROR : no authData found during the generation of the error message");
        }
        byte[] samlToken = cpepsSamlService.generateErrorAuthenticationResponse(authData,
                getSamlStatusCode(request), samlSubStatusCode,
                errorMessage, request.getRemoteAddr(), true);
        exc.setSamlTokenFail(PEPSUtil.encodeSAMLToken(samlToken));
        storkSession.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), spUrl);

    }

    private static String getInResponseTo(final HttpServletRequest req) {
        Object inResponseTo = req.getSession().getAttribute(PEPSParameters.SAML_IN_RESPONSE_TO.toString());
        return inResponseTo == null ? "error" : inResponseTo.toString();
    }

    private static String getIssuer(final HttpServletRequest req) {
        Object issuer = req.getSession().getAttribute(PEPSParameters.ISSUER.toString());
        return issuer == null ? "SPEPSExceptionHandlerServlet" : issuer.toString();
    }

    private static String getSamlStatusCode(final HttpServletRequest req) {
        Object phase = req.getSession().getAttribute(PEPSParameters.SAML_PHASE.toString());
        return phase == PEPSValues.SP_REQUEST ? STORKStatusCode.REQUESTER_URI.toString() : STORKStatusCode.RESPONDER_URI.toString();
    }

    /**
     * returned substatuscode
     */
    private static final STORKSubStatusCode STORK_SUB_STATUS_CODES[] = {
            STORKSubStatusCode.QAA_NOT_SUPPORTED,
            STORKSubStatusCode.REQUEST_DENIED_URI,
            STORKSubStatusCode.INVALID_ATTR_NAME_VALUE_URI,
            STORKSubStatusCode.AUTHN_FAILED_URI,
    };
    /**
     * PEPSErrors mapped to substatuscodes
     */
    private static final PEPSErrors PEPS_ERRORS[][] = {
            {PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_SPID,
                    PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_SPQAA, PEPSErrors.SPROVIDER_SELECTOR_INVALID_SPQAA,
                    PEPSErrors.SPROVIDER_SELECTOR_INVALID_SPQAAID},
            {PEPSErrors.SP_COUNTRY_SELECTOR_INVALID, PEPSErrors.SPWARE_CONFIG_ERROR, PEPSErrors.IDP_SAML_RESPONSE,PEPSErrors.COLLEAGUE_RESP_INVALID_SAML,},
            {PEPSErrors.SP_COUNTRY_SELECTOR_INVALID, PEPSErrors.SPWARE_CONFIG_ERROR},
            {PEPSErrors.AUTHENTICATION_FAILED_ERROR}
    };
    /**
     * PEPSErrors codes, mapped to substatuscodes
     */
    private static final String PEPS_ERRORS_CODES[][] = new String[PEPS_ERRORS.length][];

    private static String getSamlSubStatusCode(final AbstractPEPSException exc) {
        loadErrorCodesArrays();
        String subStatusCode = getSamlSubStatusCode(exc.getErrorCode());
        if(subStatusCode != null){
            return subStatusCode;
        }
        if (exc instanceof InvalidParameterPEPSException) {
            return STORKSubStatusCode.INVALID_ATTR_NAME_VALUE_URI.toString();
        }
        return STORKSubStatusCode.REQUEST_DENIED_URI.toString();// default?
    }

    private static String getSamlSubStatusCode(final String errorCode){
        for (int i = 0; i < STORK_SUB_STATUS_CODES.length; i++) {
            if (PEPS_ERRORS_CODES[i] != null && PEPS_ERRORS_CODES[i].length > 0 && Arrays.binarySearch(PEPS_ERRORS_CODES[i], errorCode) >= 0) {
                return STORK_SUB_STATUS_CODES[i].toString();
            }
        }
        return null;
    }

    /**
     *
     * @param exc
     * @return true if the exception are allowed to generate a saml message to be shown to the user
     */
    private static boolean isErrorCodeAllowed(final AbstractPEPSException exc) {
        loadErrorCodesArrays();
        String errorCode = exc.getErrorCode();
        if(isErrorCodeAllowed(errorCode)){
            return true;
        }
        if (exc instanceof InvalidParameterPEPSException || exc instanceof InvalidParameterCPEPSException) {
            return true;
        }
        return false;

    }

    private static boolean isErrorCodeAllowed(final String errorCode){
        for (int i = 0; i < STORK_SUB_STATUS_CODES.length; i++) {
            if (PEPS_ERRORS_CODES[i] != null && PEPS_ERRORS_CODES[i].length > 0 && Arrays.binarySearch(PEPS_ERRORS_CODES[i], errorCode) >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * loads error codes if needed
     */
    private static void loadErrorCodesArrays() {
        if (PEPS_ERRORS_CODES[0] == null) {
            for (int i = 0; i < PEPS_ERRORS.length; i++) {
                PEPS_ERRORS_CODES[i] = new String[PEPS_ERRORS[i].length];
                for (int j = 0; j < PEPS_ERRORS[i].length; j++) {
                    PEPS_ERRORS_CODES[i][j] = PEPSUtil.getConfig(PEPS_ERRORS[i][j].errorCode());
                }
                Arrays.sort(PEPS_ERRORS_CODES[i]);
            }
        }
    }

    /**
     *
     * @param exceptionMessage
     * @param exceptionCode
     * @param locale
     * @return the message associated with the given error (identified by exceptionMessage and exceptionCode), retrieved from sysadmin properties
     */
    public static String resolveMessage(String exceptionMessage, String exceptionCode, Locale locale){
        return prepareErrorMessage(exceptionMessage, new Object[]{exceptionCode}, locale);
    }

    private static String prepareErrorMessage(String message, Object[] parameters, Locale locale){
        try {
            ResourceBundleMessageSource msgResource = (ResourceBundleMessageSource) ApplicationContextProvider.getApplicationContext().
                    getBean(PepsBeanNames.SYSADMIN_MESSAGE_RESOURCES.toString());
            final String errorMessage = msgResource.getMessage(message, parameters, locale);
            return errorMessage;
        }catch(NoSuchMessageException e){
            LOG.warn("ERROR : message not found {} - {}", message, e);
        }
        return null;

    }

    /**
     * @param exc               the code of the message
     * @param messageParameters
     * @return the text of an error message
     */
    private static String getPepsErrorMessage(AbstractPEPSException exc, Object[] messageParameters) {
        String errorText = "";
        Throwable cause = exc.getCause();
        String code = cause == null ? exc.getMessage() : cause.getMessage();
        if (cause instanceof STORKSAMLEngineException) {
            code = ((STORKSAMLEngineException) cause).getErrorCode();
        }
        PEPSErrors err = PEPSErrors.fromID(code);
        if (PEPSErrors.isErrorCode(code) || err != null) {
            if (err == null) {
                err = PEPSErrors.fromCode(code);
            }
            String message = PEPSUtil.getConfig(err.errorMessage());

            errorText = prepareErrorMessage(message, prepareParameters(err, messageParameters), Locale.getDefault());
            if(!err.isShowToUser()){
                exc.setErrorMessage("");
            }
        }
        return errorText;
    }

    private static Object[] prepareParameters(PEPSErrors err, Object[] otherMessageParameters) {
        Object[] parameters = new Object[1 + (otherMessageParameters == null ? 0 : otherMessageParameters.length)];
        parameters[0] = PEPSUtil.getConfig(err.errorCode());
        if (otherMessageParameters != null && otherMessageParameters.length > 0) {
            System.arraycopy(otherMessageParameters, 0, parameters, 1, otherMessageParameters.length);
        }
        return parameters;
    }

}
