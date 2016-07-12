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

package eu.stork.peps.cpeps;

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.auth.engine.core.eidas.EidasAttributesTypes;
import eu.stork.peps.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.stork.peps.utils.HttpUtil;
import eu.stork.peps.utils.PropertiesUtil;
import eu.stork.peps.utils.SessionHolder;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class ColleagueRequestServlet extends AbstractCPepsServlet{
    private static final Logger LOG = LoggerFactory.getLogger(ColleagueRequestServlet.class.getName());

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if(acceptsHttpRedirect()) {
            doPost(request, response);
        }else {
            LOG.warn("BUSINESS EXCEPTION : redirect binding is not allowed");//TODO: send back a STORK error?
        }
    }

    /**
     * Post method
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PropertiesUtil.checkCPEPSActive();
        // Obtaining the assertion consumer url from SPRING context
        CPepsControllerService controllerService= (CPepsControllerService) getApplicationContext().getBean(PepsBeanNames.C_PEPS_CONTROLLER.toString());

        final IStorkSession session = controllerService.getSession();
        LOG.trace("Session content before clear " + session);
        session.clear();
        LOG.trace("== SESSION : Clear");
        // Prevent cookies from being accessed through client-side script WITHOUT renew of session.
        setHTTPOnlyHeaderToSession(false, request, response);
        SessionHolder.setId(request.getSession());
        request.getSession().setAttribute(PEPSParameters.SAML_PHASE.toString(), PEPSValues.SPEPS_REQUEST);

        // Obtains the parameters from httpRequest
        final Map<String, String> httpParameters = getHttpRequestParameters(request);

        // Validating the only HTTP parameter: SAMLRequest.
        final String samlRequest = httpParameters.get(PEPSParameters.SAML_REQUEST.toString());
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSParameters.SAML_REQUEST.toString(), samlRequest, PEPSErrors.COLLEAGUE_REQ_INVALID_SAML);

        // Storing the Remote Address and Host for auditing proposes.
        session.put(PEPSParameters.REMOTE_ADDR.toString(), httpParameters.get(PEPSParameters.REMOTE_ADDR.toString()));

        // Validating the optional HTTP Parameter relayState.
        final String relayState = httpParameters.get(PEPSParameters.RELAY_STATE.toString());
        LOG.debug("Saving CPEPS relay state. " + relayState);
        session.put(PEPSParameters.RELAY_STATE.toString(), relayState);
        httpParameters.put(PEPSParameters.HTTP_METHOD.toString(), request.getMethod());
        // Obtaining the authData
        final STORKAuthnRequest authData = controllerService.getCpepsService().processAuthenticationRequest(httpParameters, session);
//        if(util!=null && util.getConfigs()!=null && Boolean.valueOf(util.getConfigs().getProperty(PEPSParameters.VALIDATE_BINDING.toString()))) {
//            PEPSUtil.validateBinding(authData, request.getMethod(), PEPSErrors.COLLEAGUE_REQ_INVALID_SAML);
//        }
        if (!StringUtils.isBlank(relayState)) { // RelayState's HTTP Parameter is optional!
            PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSParameters.RELAY_STATE.toString(), relayState, PEPSErrors.SPROVIDER_SELECTOR_INVALID_RELAY_STATE);
        }
        // Validating the personal attribute list
        final IPersonalAttributeList persAttrList = authData.getPersonalAttributeList();
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSParameters.ATTRIBUTE_LIST.toString(), persAttrList);
        List<PersonalAttribute> attrList = new ArrayList<PersonalAttribute>();
        Boolean eidasAttributes=false;
        for(PersonalAttribute pa:persAttrList){
            //should use the iterator because it provides the items in their insert order
            EidasAttributesTypes eat = EIDASAttributes.ATTRIBUTES_SET.get(pa.getFullName());
            pa.setEidasLegalPersonAttr(eat!=null &&(eat==EidasAttributesTypes.LEGAL_PERSON_MANDATORY||eat==EidasAttributesTypes.LEGAL_PERSON_OPTIONAL));
            pa.setEidasNaturalPersonAttr(eat != null && (eat == EidasAttributesTypes.NATURAL_PERSON_MANDATORY || eat == EidasAttributesTypes.NATURAL_PERSON_OPTIONAL));
            if(eat!=null){
                eidasAttributes=true;
            }
            attrList.add(pa);
        }
        String redirectUrl = authData.getAssertionConsumerServiceURL();
        LOG.debug("RedirectUrl: " + redirectUrl);
        // Validating the citizenConsentUrl
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(),PEPSParameters.CPEPS_REDIRECT_URL.toString(), controllerService.getCitizenConsentUrl(), PEPSErrors.COLLEAGUE_REQ_INVALID_DEST_URL);
        LOG.debug("sessionId is on cookies () or fromURL ", request.isRequestedSessionIdFromCookie(), request.isRequestedSessionIdFromURL());
        request.setAttribute(PepsBeanNames.SAML_TOKEN_FAIL.toString(), controllerService.getCpepsService().generateSamlTokenFail(authData, PEPSErrors.CITIZEN_RESPONSE_MANDATORY, httpParameters.get(PEPSParameters.REMOTE_ADDR.toString())));
        request.setAttribute(PepsBeanNames.SP_ID.toString(), authData.getProviderName());
        request.setAttribute(PepsBeanNames.QAA_LEVEL.toString(), authData.getQaa());
        request.setAttribute(PepsBeanNames.LOA_VALUE.toString(), authData.getEidasLoA());
        request.setAttribute(PepsBeanNames.CITIZEN_CONSENT_URL.toString(), encodeURL(controllerService.getCitizenConsentUrl(), response)); // Correct URl redirect cookie implementation
        request.setAttribute(PepsBeanNames.ATTR_LIST.toString(), attrList);
        request.setAttribute(PepsBeanNames.REDIRECT_URL.toString(), encodeURL(redirectUrl, response));// Correct URl redirect cookie implementation
        request.setAttribute(PepsBeanNames.EIDAS_ATTRIBUTES_PARAM.toString(), eidasAttributes);

        if (controllerService.isAskConsentType()) {
            RequestDispatcher dispatcher = request.getRequestDispatcher(encodeURL(PepsViewNames.CPEPS_PRESENT_CONSENT.toString(), response));
            dispatcher.forward(request, response);
        } else {
            String forwardUrl;
            if(request.getMethod()==STORKAuthnRequest.BINDING_REDIRECT) {
                forwardUrl = HttpUtil.rebuildGetUrl(PepsViewNames.CPEPS_NO_CONSENT.toString(), request, response);
            }else {
                forwardUrl = encodeURL(PepsViewNames.CPEPS_NO_CONSENT.toString(), response);
            }
            RequestDispatcher dispatcher = request.getRequestDispatcher(forwardUrl);
            dispatcher.forward(request, response);
        }
    }

}
