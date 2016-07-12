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

package eu.stork.peps.speps;

import eu.stork.peps.ApplicationContextProvider;
import eu.stork.peps.auth.commons.*;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.auth.commons.exceptions.AbstractPEPSException;
import eu.stork.peps.auth.speps.AUSPEPSUtil;
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
 * S-PEPS can communicate with.
 */

public final class CountrySelectorServlet extends AbstractSPepsServlet {

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

            AUSPEPSUtil auspepsUtil= ApplicationContextProvider.getApplicationContext().getBean(AUSPEPSUtil.class);
            if(auspepsUtil!=null && auspepsUtil.getConfigs()!=null && null!=auspepsUtil.getConfigs().getProperty(PEPSValues.SPEPS_SUPPORT_FRAMING_REQUEST.toString())
                    && !Boolean.parseBoolean(auspepsUtil.getConfigs().getProperty(PEPSValues.SPEPS_SUPPORT_FRAMING_REQUEST.toString()))){
                RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(PepsViewNames.SPEPS_COUNTRY_FRAMING.toString());
                dispatcher.forward(request, response);
                return;
            }
            // Prevent cookies from being accessed through client-side script.
            setHTTPOnlyHeaderToSession(false, request, response);

            // Obtaining the assertion consumer url from SPRING context
            SPepsControllerService controllerService = (SPepsControllerService) getApplicationContext().getBean(PepsBeanNames.S_PEPS_CONTROLLER.toString());
            LOG.trace(controllerService.toString());

            final Map<String, String> parameters = getHttpRequestParameters(request);

            // Validate HTTP Parameter SP URL
            PEPSUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    PEPSParameters.SP_URL.toString(), parameters.get(PEPSParameters.SP_URL.toString()),
                    PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_SPURL);

            spUrl = parameters.get(PEPSParameters.SP_URL.toString());
            request.getSession().setAttribute(PEPSParameters.SP_URL.toString(), spUrl);
            parameters.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), spUrl);
            controllerService.getSession().put(PEPSParameters.ERROR_REDIRECT_URL.toString(), spUrl);

            // Validate HTTP Parameter attrList
            PEPSUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    PEPSParameters.ATTRIBUTE_LIST.toString(), parameters.get(PEPSParameters.ATTRIBUTE_LIST.toString()),
                    PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_ATTR);

            // Validate HTTP Parameter SP QAALevel
            PEPSUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    PEPSParameters.SP_QAALEVEL.toString(), parameters.get(PEPSParameters.SP_QAALEVEL.toString()),
                    PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_SPQAA);

            // Validate HTTP Parameter SP ID
            PEPSUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    PEPSParameters.SP_ID.toString(), parameters.get(PEPSParameters.SP_ID.toString()),
                    PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_SPID);

            // Validate HTTP Parameter ProviderName
            if (StringUtils.isNotEmpty(providerName)) {
                PEPSUtil.validateParameter(
                        CountrySelectorServlet.class.getCanonicalName(),
                        PEPSParameters.PROVIDER_NAME_VALUE.toString(), parameters.get(PEPSParameters.PROVIDER_NAME_VALUE.toString()),
                        PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_PROVIDER_NAME);
            }

            final byte[] samlToken =
                    controllerService.getSpepsService().processCountrySelector(parameters);

            countries = controllerService.getSpepsService().getCountrySelectorList();

            LOG.debug("Countries: " + countries.toString());
            sAMLRequest = PEPSUtil.encodeSAMLToken(samlToken);
            PEPSUtil.validateParameter(CountrySelectorServlet.class.getCanonicalName(),
                    PEPSParameters.SAML_REQUEST.toString(), sAMLRequest,
                    PEPSErrors.SP_COUNTRY_SELECTOR_ERROR_CREATE_SAML);

            request.setAttribute(PEPSParameters.PEPS_AUTH_CONSENT.toString(), controllerService.getPepsAuth());
            request.setAttribute(PEPSParameters.SAML_REQUEST.toString(), sAMLRequest);
            request.setAttribute(PEPSParameters.SP_METADATA_URL.toString(), parameters.get(PEPSParameters.SP_METADATA_URL.toString()));
            request.setAttribute("countries", countries);

            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(PepsViewNames.SPEPS_COUNTRY_SELECTOR.toString());
            dispatcher.forward(request, response);

        } catch (AbstractPEPSException e) {
            LOG.info("BUSINESS EXCEPTION : country selector servlet", e.getErrorMessage());
            LOG.debug("BUSINESS EXCEPTION : country selector servlet", e);
            throw e;
        }
    }
}
