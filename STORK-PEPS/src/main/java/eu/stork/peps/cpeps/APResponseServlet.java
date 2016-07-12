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
import eu.stork.peps.auth.commons.exceptions.InvalidSessionPEPSException;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.auth.engine.core.eidas.EidasAttributesTypes;
import eu.stork.peps.auth.engine.core.validator.eidas.EIDASAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Action that handles the incoming response from the Attribute Provider.
 *
 * @see eu.stork.peps.cpeps.AbstractCPepsServlet
 */
public final class APResponseServlet extends AbstractCPepsServlet {


  /**
   * Unique identifier.
   */
  private static final long serialVersionUID = 4539991356226362922L;

  @Override
  protected Logger getLogger() {
    return LOG;
  }
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(APResponseServlet.class.getName());


  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    execute(request, response);
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    execute(request, response);
  }

  /**
   * Executes the method {@link eu.stork.peps.auth.cpeps.AUCPEPS#processAPResponse} (of C-PEPS) and then
   * sets the internal variables used by the redirection JSP or the
   * consent-value jsp, accordingly to {@link eu.stork.peps.auth.commons.PEPSParameters#NO_CONSENT_VALUE}
   * or {@link eu.stork.peps.auth.commons.PEPSParameters#CONSENT_VALUE} respectively.
   *
   * @return {@link eu.stork.peps.auth.commons.PEPSParameters#CONSENT_VALUE} if the consent-value form is
   *         to be displayed, {@link eu.stork.peps.auth.commons.PEPSParameters#NO_CONSENT_VALUE} otherwise.
   *
   * @see eu.stork.peps.auth.commons.PEPSParameters#NO_CONSENT_VALUE
   * @see eu.stork.peps.auth.commons.PEPSParameters#CONSENT_VALUE
   * @param request
   * @param response
   */

  private void execute(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    try {

      RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(handleExecute(request, response));
      dispatcher.forward(request, response);
      if(request.getSession().getAttribute(PEPSParameters.SPEPS_SESSION.toString())==null) {
        request.getSession().invalidate();
      }
    } catch (ServletException e) {
      getLogger().info("ERROR : ServletException {}", e.getMessage());
      getLogger().debug("ERROR : ServletException {}", e);
      throw e;
    } catch (IOException e) {
      getLogger().info("IOException {}", e.getMessage());
      getLogger().debug("IOException {}", e);
      throw e;
    }

  }
  private String handleExecute(HttpServletRequest request, HttpServletResponse response){
    String redirectUrl;
    String samlToken;
    String samlTokenFail = null;
    List<PersonalAttribute> pal;
    String spId;
    int qaaLevel;
    PersonalAttributeList attrList = (PersonalAttributeList) request.getAttribute(PEPSParameters.ATTRIBUTE_LIST.toString());

    // Obtaining the assertion consumer url from SPRING context
    APResponseBean controllerService = (APResponseBean) getApplicationContext().getBean(PepsBeanNames.AP_RESPONSE.toString());

    // Validate if we have all the session attributes.
    synchronized (controllerService.getSession()) {
      getLogger().debug("Session content " + controllerService.getSession());
      if (controllerService.getSession().get(PEPSParameters.AUTH_REQUEST.toString()) == null
              || controllerService.getSession().get(PEPSParameters.REMOTE_ADDR.toString()) == null) {
        getLogger().info("BUSINESS EXCEPTION : Session is null or invalid!");
        throw new InvalidSessionPEPSException(
                PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorCode()),
                PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorMessage()));
      }
    }

    // Prevent cookies from being accessed through client-side script.
    setHTTPOnlyHeaderToSession(false, request, response);

    IStorkSession storkSession = controllerService.getSession();

    // Gets the attributes from Attribute Providers and validates mandatory
    // attributes.
    final Map<String, String> parameters = getHttpRequestParameters(request);
    parameters.put(PEPSParameters.ATTRIBUTE_LIST.toString(),
            attrList.toString());

    String relayState = parameters.get(PEPSParameters.RELAY_STATE.toString());

    if (storkSession.containsKey(PEPSParameters.RELAY_STATE.toString())) {
      relayState = (String) storkSession.get(
              PEPSParameters.RELAY_STATE.toString());
      getLogger().debug("Relay State CPEPS " + relayState);
    }

    final STORKAuthnRequest authData =
            controllerService.getCpepsService().processAPResponse(parameters, storkSession);
    final IPersonalAttributeList localPal = authData.getPersonalAttributeList();

    // Setting internal variables, to be included by the Struts on the JSP
    getLogger().trace("setting internal variables");
    samlToken = new String(authData.getTokenSaml(), Charset.forName("UTF-8"));

    pal = new ArrayList<PersonalAttribute>();
    Boolean eidasAttributes=false;
    for(PersonalAttribute pa:localPal){
      //should use the iterator because it provides the items in their insert order
      EidasAttributesTypes eat = EIDASAttributes.ATTRIBUTES_SET.get(pa.getFullName());
      pa.setEidasLegalPersonAttr(eat!=null &&(eat==EidasAttributesTypes.LEGAL_PERSON_MANDATORY||eat==EidasAttributesTypes.LEGAL_PERSON_OPTIONAL));
      pa.setEidasNaturalPersonAttr(eat != null && (eat == EidasAttributesTypes.NATURAL_PERSON_MANDATORY || eat == EidasAttributesTypes.NATURAL_PERSON_OPTIONAL));
      if(eat!=null){
        eidasAttributes=true;
      }
      pal.add(pa);
    }
    redirectUrl = authData.getAssertionConsumerServiceURL();
    getLogger().debug("redirectUrl: " + redirectUrl);
    spId = authData.getProviderName();
    qaaLevel = authData.getQaa();

    getLogger().debug("Session clear");
    storkSession.clear();

    String retVal;

    if (controllerService.isAskConsentValue()) {
      getLogger().trace("consent-value");
      retVal = PepsViewNames.CPEPS_CITIZEN_CONSENT.toString();
      getLogger().trace("Generate SAMLTokenFail");
      samlTokenFail =
              controllerService.getCpepsService().generateSamlTokenFail(
                      authData,
                      PEPSErrors.CITIZEN_NO_CONSENT_MANDATORY,
                      getHttpRequestParameters(request).get(
                              PEPSParameters.REMOTE_ADDR.toString()));

    } else {
      getLogger().trace("no-consent-value");
      retVal = PepsViewNames.SPEPS_REDIRECT.toString();
    }

    request.setAttribute(PepsBeanNames.REDIRECT_URL.toString(), response.encodeRedirectURL(redirectUrl)); // Correct URl redirect cookie implementation
    request.setAttribute(PepsBeanNames.SAML_TOKEN.toString(), samlToken);
    request.setAttribute(PepsBeanNames.SAML_TOKEN_FAIL.toString(), samlTokenFail);
    request.setAttribute(PepsBeanNames.PAL.toString(), pal);
    request.setAttribute(PepsBeanNames.SP_ID.toString(), spId);
    request.setAttribute(PepsBeanNames.QAA_LEVEL.toString(),qaaLevel);
    if(eidasAttributes) {
      request.setAttribute(PepsBeanNames.LOA_VALUE.toString(), authData.getEidasLoA());
    }
    request.setAttribute(PepsBeanNames.RELAY_STATE.toString(), relayState);
    request.setAttribute(PepsBeanNames.EIDAS_ATTRIBUTES_PARAM.toString(), eidasAttributes);
    return retVal;
  }
}
