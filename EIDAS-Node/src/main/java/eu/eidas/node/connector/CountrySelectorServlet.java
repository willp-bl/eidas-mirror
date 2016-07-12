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

package eu.eidas.node.connector;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.node.ApplicationContextProvider;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;
import eu.eidas.node.auth.connector.AUCONNECTORUtil;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * This class responds to the Service Provider with the countries that this
 * Connector can communicate with.
 */

public final class CountrySelectorServlet extends AbstractConnectorServlet {

    private static final long serialVersionUID = 1367104774461146578L;
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(CountrySelectorServlet.class.getName());

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        /**
         * List of supported countries.
         */
        List<Country> countries;

        /**
         * SAML token containing a request.
         */
        String sAMLRequest;

        /**
         * Id of the providerName.
         */
        String providerName = null;

        /**
         * URL of the SP.
         */
        String spUrl;

        try {

            AUCONNECTORUtil auConnectorUtil= ApplicationContextProvider.getApplicationContext().getBean(AUCONNECTORUtil.class);
            if(auConnectorUtil!=null && auConnectorUtil.getConfigs()!=null && null!=auConnectorUtil.getConfigs().getProperty(EIDASValues.EIDAS_CONNECTOR_SUPPORT_FRAMING_REQUEST.toString())
                    && !Boolean.parseBoolean(auConnectorUtil.getConfigs().getProperty(EIDASValues.EIDAS_CONNECTOR_SUPPORT_FRAMING_REQUEST.toString()))){
                RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(NodeViewNames.EIDAS_CONNECTOR_COUNTRY_FRAMING.toString());
                dispatcher.forward(request, response);
                return;
            }
            // Prevent cookies from being accessed through client-side script.
            setHTTPOnlyHeaderToSession(false, request, response);

            // Obtaining the assertion consumer url from SPRING context
            ConnectorControllerService controllerService = (ConnectorControllerService) getApplicationContext().getBean(NodeBeanNames.EIDAS_CONNECTOR_CONTROLLER.toString());
            LOG.trace(controllerService.toString());

            final Map<String, String> parameters = getHttpRequestParameters(request);

            // Validate HTTP Parameter SP URL
            EIDASUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    EIDASParameters.SP_URL.toString(), parameters.get(EIDASParameters.SP_URL.toString()),
                    EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_SPURL);

            spUrl = parameters.get(EIDASParameters.SP_URL.toString());
            request.getSession().setAttribute(EIDASParameters.SP_URL.toString(), spUrl);
            parameters.put(EIDASParameters.ERROR_REDIRECT_URL.toString(), spUrl);
            controllerService.getSession().put(EIDASParameters.ERROR_REDIRECT_URL.toString(), spUrl);

            // Validate HTTP Parameter attrList
            EIDASUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    EIDASParameters.ATTRIBUTE_LIST.toString(), parameters.get(EIDASParameters.ATTRIBUTE_LIST.toString()),
                    EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_ATTR);

            // Validate HTTP Parameter SP QAALevel
            EIDASUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    EIDASParameters.SP_QAALEVEL.toString(), parameters.get(EIDASParameters.SP_QAALEVEL.toString()),
                    EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_SPQAA);

            // Validate HTTP Parameter SP ID
            EIDASUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    EIDASParameters.SP_ID.toString(), parameters.get(EIDASParameters.SP_ID.toString()),
                    EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_SPID);

            // Validate HTTP Parameter ProviderName
            if (StringUtils.isNotEmpty(providerName)) {
                EIDASUtil.validateParameter(
                        CountrySelectorServlet.class.getCanonicalName(),
                        EIDASParameters.PROVIDER_NAME_VALUE.toString(), parameters.get(EIDASParameters.PROVIDER_NAME_VALUE.toString()),
                        EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_PROVIDER_NAME);
            }

            final byte[] samlToken =
                    controllerService.getConnectorService().processCountrySelector(parameters);

            countries = controllerService.getConnectorService().getCountrySelectorList();

            LOG.debug("Countries: " + countries.toString());
            sAMLRequest = EIDASUtil.encodeSAMLToken(samlToken);
            EIDASUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    EIDASParameters.SAML_REQUEST.toString(), sAMLRequest,
                    EIDASErrors.SP_COUNTRY_SELECTOR_ERROR_CREATE_SAML);

            request.setAttribute(EIDASParameters.EIDAS_AUTH_CONSENT.toString(), controllerService.getNodeAuth());
            request.setAttribute(EIDASParameters.SAML_REQUEST.toString(), sAMLRequest);
            request.setAttribute(EIDASParameters.SP_METADATA_URL.toString(), parameters.get(EIDASParameters.SP_METADATA_URL.toString()));
            request.setAttribute("countries", countries);

            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(NodeViewNames.EIDAS_CONNECTOR_COUNTRY_SELECTOR.toString());
            dispatcher.forward(request, response);

        } catch (AbstractEIDASException e) {
            LOG.info("BUSINESS EXCEPTION : country selector servlet", e.getErrorMessage());
            LOG.debug("BUSINESS EXCEPTION : country selector servlet", e);
            throw e;
        }
    }
}
