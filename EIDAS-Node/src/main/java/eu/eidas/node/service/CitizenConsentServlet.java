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

package eu.eidas.node.service;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.node.ApplicationContextProvider;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;
import eu.eidas.node.auth.service.AUSERVICEUtil;
import eu.eidas.node.security.Token;
import eu.eidas.node.utils.HttpUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * @author vanegdi
 */
public class CitizenConsentServlet extends AbstractServiceServlet {
    private static final Logger LOG = LoggerFactory.getLogger(CitizenConsentServlet.class.getName());

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if(acceptsHttpRedirect()) {
            doPost(request, response);
        }else {
            LOG.info("DoGet called but redirect binding is not allowed");
        }
    }

    /**
     * Post method
     *
     * @param request
     * @param response
     * @throws javax.servlet.ServletException
     * @throws java.io.IOException
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            ServiceControllerService controllerService = (ServiceControllerService) getApplicationContext().getBean(NodeBeanNames.EIDAS_SERVICE_CONTROLLER.toString());
            final IEIDASSession session = controllerService.getSession();
            synchronized (session) {
                LOG.debug("Session content " + session);
                if (session.get(EIDASParameters.AUTH_REQUEST.toString()) == null || session.get(EIDASParameters.REMOTE_ADDR.toString()) == null) {
                    LOG.info("BUSINESS EXCEPTION : Session is null or has missing attributes!");
                    throw new InvalidSessionEIDASException(EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorCode()),
                            EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorMessage()));
                }
            }

            // Prevent cookies from being accessed through client-side script.
            setHTTPOnlyHeaderToSession(false, request, response);
            // Checking for CSRF token
            if(controllerService.isAskConsentType()) {
                Token.checkToken(request);
            }
            // Obtains the parameters from httpRequest
            IPersonalAttributeList attrList = controllerService.getProxyService().processCitizenConsent(getHttpRequestParameters(request), session, controllerService.isAskConsentType());
            // Correct URl redirect cookie implementation
            String callbackURL=encodeURL(controllerService.getCallBackURL(), response);

            request.setAttribute(NodeBeanNames.ATTR_LIST.toString(), attrList);
            request.setAttribute(NodeBeanNames.CALLBACK_URL.toString(), callbackURL);
            boolean signIdpResponseAssertion=false, forceEncryptIdpResponse=false;
            AUSERVICEUtil util= ApplicationContextProvider.getApplicationContext().getBean(AUSERVICEUtil.class);
            if(util!=null && util.getConfigs()!=null && Boolean.valueOf(util.getConfigs().getProperty(EIDASParameters.RESPONSE_SIGN_ASSERTION.toString()))) {
                signIdpResponseAssertion=true;
            }
            if(util!=null && util.getConfigs()!=null && Boolean.valueOf(util.getConfigs().getProperty(EIDASParameters.RESPONSE_ENCRYPT_ASSERTION.toString()))) {
                forceEncryptIdpResponse = true;
            }
            request.setAttribute(EIDASParameters.RESPONSE_SIGN_ASSERTION.toString(), signIdpResponseAssertion);
            request.setAttribute(EIDASParameters.RESPONSE_ENCRYPT_ASSERTION.toString(), forceEncryptIdpResponse);

            String citizenAuthURL=NodeViewNames.CITIZEN_AUTHENTICATION.toString();
            if(request.getMethod()==EIDASAuthnRequest.BINDING_REDIRECT) {
                citizenAuthURL = HttpUtil.rebuildGetUrl(citizenAuthURL, request, response);
            }
            RequestDispatcher dispatcher = request.getRequestDispatcher(citizenAuthURL);
            dispatcher.forward(request, response);
        } catch (AbstractEIDASException e) {
            LOG.info("BUSINESS EXCEPTION : ", e.getErrorMessage());
            throw e;
        }
    }
}
