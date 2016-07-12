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
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;

import eu.eidas.node.utils.SessionHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidParameterException;
import java.util.Map;

/**
 * Is invoked when ProxyService wants to pass control to the Connector.
 */
public final class ColleagueResponseServlet extends AbstractConnectorServlet {

  private static final long serialVersionUID = -2511363089207242981L;
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(ColleagueResponseServlet.class.getName());

  @Override
  protected Logger getLogger() {
    return LOG;
  }


  private boolean validateParameterAndIsNormalSAMLResponse(String sAMLResponse) {
    // Validating the only HTTP parameter: sAMLResponse.
    try {
      LOG.trace("Validating Parameter SAMLResponse");
      EIDASUtil.validateParameter(
              ColleagueResponseServlet.class.getCanonicalName(),
              EIDASParameters.SAML_RESPONSE.toString(), sAMLResponse,
              EIDASErrors.COLLEAGUE_RESP_INVALID_SAML);
      return true;
    } catch (InvalidParameterEIDASException e) {
        LOG.info("ERROR : SAMLResponse parameter is missing",e.getMessage());
        LOG.debug("ERROR : SAMLResponse parameter is missing",e);
        throw new InvalidParameterException("SAMLResponse parameter is missing");
      }
  }

    /**
     * This call is used for the moa/mocca get
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }

  /**
   * Executes {@link eu.eidas.node.auth.connector.AUCONNECTOR#getAuthenticationResponse} and prepares the citizen
   * to be redirected back to the SP.
   * @param request
   * @param response
   * @return
   * @throws Exception
   */
  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String sAMLResponse;
    String relayState = null;
    String spUrl;
    try {
      // Prevent cookies from being accessed through client-side script with renew of session.
      setHTTPOnlyHeaderToSession(false, request, response);
      SessionHolder.setId(request.getSession());
      request.getSession().setAttribute(EIDASParameters.SAML_PHASE.toString(), EIDASValues.EIDAS_CONNECTOR_RESPONSE);

      // Obtaining the assertion consumer url from SPRING context
      ConnectorControllerService controllerService= (ConnectorControllerService) getApplicationContext().getBean(NodeBeanNames.EIDAS_CONNECTOR_CONTROLLER.toString());
      LOG.trace("ConnectorControllerService {}", controllerService);

      IEIDASSession eidasSession = controllerService.getSession();
      LOG.debug("== SESSION : execute, size is " + eidasSession.size());

      // Obtains the parameters from httpRequest
      final Map<String, String> parameters = getHttpRequestParameters(request);

      if(parameters.containsKey(EIDASParameters.SAML_RESPONSE.toString())) {
          sAMLResponse = parameters.get(EIDASParameters.SAML_RESPONSE.toString());
      } else {
          sAMLResponse = "";
      }

      // Validating the only HTTP parameter: sAMLResponse or samlArtifact.
    spUrl = (String) eidasSession.get(EIDASParameters.SP_URL.toString());
    if(controllerService.getConnectorService().isPluginResponse(request)){
        sAMLResponse=controllerService.getConnectorService().processPluginResponse(request, response, getServletContext(), eidasSession, parameters);
        if(sAMLResponse == null){
            return;//the plugin performed the dispatching itself
        }
    } else {
        if (!validateParameterAndIsNormalSAMLResponse(sAMLResponse)) {
            LOG.info("ERROR : Cannot validate parameter or abnormal SAML response");
        }
        LOG.trace("Normal SAML response decoding");
        final EIDASAuthnRequest authData = controllerService.getConnectorService().getAuthenticationResponse(parameters, eidasSession);

        EIDASUtil.validateParameter(
                ColleagueResponseServlet.class.getCanonicalName(),
                EIDASParameters.SP_URL.toString(), spUrl);

        // Setting internal variables
        LOG.trace("Setting internal variables");

        if (eidasSession.containsKey(EIDASParameters.RELAY_STATE.toString())) {
          relayState = ((String) eidasSession.get(EIDASParameters.RELAY_STATE.toString()));
        }

        sAMLResponse = new String(authData.getTokenSaml(), Charset.forName("UTF-8"));
        EIDASUtil.validateParameter(  ColleagueResponseServlet.class.getCanonicalName(),
                EIDASParameters.SAML_RESPONSE.toString(), sAMLResponse);

        eidasSession.clear();
    }

      request.setAttribute(NodeBeanNames.SAML_RESPONSE.toString(), sAMLResponse);
      request.setAttribute(NodeBeanNames.RELAY_STATE.toString(), relayState);
      request.setAttribute(NodeBeanNames.SP_URL.toString(),spUrl);

      RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(NodeViewNames.EIDAS_CONNECTOR_COLLEAGUE_RESPONSE_REDIRECT.toString());
      dispatcher.forward(request,response);
    }catch (ServletException se){
      LOG.info("BUSINESS EXCEPTION : ServletException", se.getMessage());
      LOG.debug("BUSINESS EXCEPTION : ServletException", se);
      throw se;
    }catch (IOException ie){
      LOG.info("BUSINESS EXCEPTION : IOException", ie.getMessage());
      LOG.debug("BUSINESS EXCEPTION : IOException", ie);
      throw ie;
    }
  }

}
