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

import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
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
 * Is invoked when C-PEPS wants to pass control to the S-PEPS.
 */
public final class ColleagueResponseServlet extends AbstractSPepsServlet {

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
      PEPSUtil.validateParameter(
              ColleagueResponseServlet.class.getCanonicalName(),
              PEPSParameters.SAML_RESPONSE.toString(), sAMLResponse,
              PEPSErrors.COLLEAGUE_RESP_INVALID_SAML);
      return true;
    } catch (InvalidParameterPEPSException e) {
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
   * Executes {@link eu.stork.peps.auth.speps.AUSPEPS#getAuthenticationResponse} and prepares the citizen
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

      // Obtaining the assertion consumer url from SPRING context
      SPepsControllerService controllerService= (SPepsControllerService) getApplicationContext().getBean(PepsBeanNames.S_PEPS_CONTROLLER.toString());
      LOG.trace("SpepsControllerService {}", controllerService);

      IStorkSession storkSession = controllerService.getSession();
      LOG.debug("== SESSION : execute, size is " + storkSession.size());

      // Obtains the parameters from httpRequest
      final Map<String, String> parameters = getHttpRequestParameters(request);

      if(parameters.containsKey(PEPSParameters.SAML_RESPONSE.toString())) {
          sAMLResponse = parameters.get(PEPSParameters.SAML_RESPONSE.toString());
      } else {
          sAMLResponse = "";
      }

      // Validating the only HTTP parameter: sAMLResponse or samlArtifact.
    spUrl = (String) storkSession.get(PEPSParameters.SP_URL.toString());
    if(controllerService.getSpepsService().isPluginResponse(request)){
        sAMLResponse=controllerService.getSpepsService().processPluginResponse(request, response, getServletContext(), storkSession, parameters);
        if(sAMLResponse == null){
            return;//the plugin performed the dispatching itself
        }
    } else {
        if (!validateParameterAndIsNormalSAMLResponse(sAMLResponse)) {
            LOG.info("ERROR : Cannot validate parameter or abnormal SAML response");
        }
        LOG.trace("Normal SAML response decoding");
        final STORKAuthnRequest authData = controllerService.getSpepsService().getAuthenticationResponse(parameters, storkSession);

        PEPSUtil.validateParameter(
                ColleagueResponseServlet.class.getCanonicalName(),
                PEPSParameters.SP_URL.toString(), spUrl);

        // Setting internal variables
        LOG.trace("Setting internal variables");

        if (storkSession.containsKey(PEPSParameters.RELAY_STATE.toString())) {
          relayState = ((String) storkSession.get(PEPSParameters.RELAY_STATE.toString()));
        }

        sAMLResponse = new String(authData.getTokenSaml(), Charset.forName("UTF-8"));
        PEPSUtil.validateParameter(  ColleagueResponseServlet.class.getCanonicalName(),
                PEPSParameters.SAML_RESPONSE.toString(), sAMLResponse);

        storkSession.clear();
    }

      request.setAttribute(PepsBeanNames.SAML_RESPONSE.toString(), sAMLResponse);
      request.setAttribute(PepsBeanNames.RELAY_STATE.toString(), relayState);
      request.setAttribute(PepsBeanNames.SP_URL.toString(),spUrl);

      RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(PepsViewNames.SPEPS_COLLEAGUE_RESPONSE_REDIRECT.toString());
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
