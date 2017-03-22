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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.EidasErrors;
import eu.eidas.auth.commons.IncomingRequest;
import eu.eidas.auth.commons.WebRequest;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.tx.CorrelationMap;
import eu.eidas.auth.commons.tx.StoredAuthenticationRequest;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeParameterNames;
import eu.eidas.node.security.Token;
import eu.eidas.node.specificcommunication.ISpecificProxyService;
import eu.eidas.node.specificcommunication.exception.SpecificException;

@SuppressWarnings("squid:S1989") // due to the code uses correlation maps, not http sessions
public class CitizenConsentServlet extends AbstractServiceServlet {

    private static final Logger LOG = LoggerFactory.getLogger(CitizenConsentServlet.class.getName());

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (acceptsHttpRedirect()) {
            doPost(request, response);
        } else {
            LOG.info("DoGet called but redirect binding is not allowed");
        }
    }

    /**
     * Post method
     *
     * @param request the request
     * @param response the response
     * @throws javax.servlet.ServletException
     * @throws java.io.IOException
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            ServiceControllerService controllerService = (ServiceControllerService) getApplicationContext().getBean(
                    NodeBeanNames.EIDAS_SERVICE_CONTROLLER.toString());

            // We arrive with an attribute if there was no consent:
            String samlRequestId = (String) request.getAttribute(NodeParameterNames.REQUEST_ID.toString());
            StoredAuthenticationRequest storedRequest = null;

            if (null == samlRequestId) {
                // We arrive with a parameter if there was a consent and the consent form was submitted:
                samlRequestId = request.getParameter(NodeParameterNames.REQUEST_ID.toString());
            }

            if (null != samlRequestId) {
                CorrelationMap<StoredAuthenticationRequest> requestCorrelationMap =
                        controllerService.getProxyServiceRequestCorrelationMap();
                storedRequest = requestCorrelationMap.get(samlRequestId);
            }

            if (null == storedRequest) {
                LOG.info("BUSINESS EXCEPTION : Session is null or has missing attributes!");
                throw new InvalidSessionEIDASException(EidasErrors.get(EidasErrorKey.INVALID_SESSION.errorCode()),
                                                       EidasErrors.get(EidasErrorKey.INVALID_SESSION.errorMessage()));
            }

            request.setAttribute(NodeParameterNames.REQUEST_ID.toString(), samlRequestId);

            // Prevent cookies from being accessed through client-side script.
            setHTTPOnlyHeaderToSession(false, request, response);
            // Checking for CSRF token
            if (controllerService.isAskConsentType()) {
                Token.checkToken(request);
            }
            // Obtains the parameters from httpRequest
            WebRequest webRequest = new IncomingRequest(request);
            IAuthenticationRequest authenticationRequest = controllerService.getProxyService()
                    .processCitizenConsent(webRequest, storedRequest, controllerService.isAskConsentType());

            // send the request to the specific module:
            ISpecificProxyService specificProxyService = controllerService.getSpecificProxyService();
            LightRequest specificRequest = LightRequest.builder(authenticationRequest).build();
            specificProxyService.sendRequest(specificRequest, request, response);

        } catch (AbstractEIDASException e) {
            LOG.info("BUSINESS EXCEPTION : " + e, e);
            throw e;
        } catch (SpecificException e) {
            LOG.info("BUSINESS EXCEPTION : " + e, e);
            throw new ServletException(e);
        }
    }
}
