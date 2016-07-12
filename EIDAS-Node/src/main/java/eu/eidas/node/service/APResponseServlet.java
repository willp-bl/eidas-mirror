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
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.auth.engine.core.eidas.EidasAttributesTypes;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;

import eu.eidas.node.utils.EidasAttributesUtil;
import eu.eidas.node.utils.SessionHolder;
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
 * @see eu.eidas.node.service.AbstractServiceServlet
 */
public final class APResponseServlet extends AbstractServiceServlet {


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
   * Executes the method {@link eu.eidas.node.auth.service.AUSERVICE#processAPResponse} (of the ProxyService) and then
   * sets the internal variables used by the redirection JSP or the
   * consent-value jsp, accordingly to {@link eu.eidas.auth.commons.EIDASParameters#NO_CONSENT_VALUE}
   * or {@link eu.eidas.auth.commons.EIDASParameters#CONSENT_VALUE} respectively.
   *
   * @return {@link eu.eidas.auth.commons.EIDASParameters#CONSENT_VALUE} if the consent-value form is
   *         to be displayed, {@link eu.eidas.auth.commons.EIDASParameters#NO_CONSENT_VALUE} otherwise.
   *
   * @see eu.eidas.auth.commons.EIDASParameters#NO_CONSENT_VALUE
   * @see eu.eidas.auth.commons.EIDASParameters#CONSENT_VALUE
   * @param request
   * @param response
   */

  private void execute(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    try {

      RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(handleExecute(request, response));
      dispatcher.forward(request, response);
      if(request.getSession().getAttribute(EIDASParameters.EIDAS_CONNECTOR_SESSION.toString())==null) {
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
    SessionHolder.setId(request.getSession());
    request.getSession().setAttribute(EIDASParameters.SAML_PHASE.toString(), EIDASValues.EIDAS_SERVICE_RESPONSE);

    PersonalAttributeList attrList = (PersonalAttributeList) request.getAttribute(EIDASParameters.ATTRIBUTE_LIST.toString());

    // Obtaining the assertion consumer url from SPRING context
    APResponseBean controllerService = (APResponseBean) getApplicationContext().getBean(NodeBeanNames.AP_RESPONSE.toString());

    // Validate if we have all the session attributes.
    synchronized (controllerService.getSession()) {
      getLogger().debug("Session content " + controllerService.getSession());
      if (controllerService.getSession().get(EIDASParameters.AUTH_REQUEST.toString()) == null
              || controllerService.getSession().get(EIDASParameters.REMOTE_ADDR.toString()) == null) {
        getLogger().info("BUSINESS EXCEPTION : Session is null or invalid!");
        throw new InvalidSessionEIDASException(
                EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorCode()),
                EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorMessage()));
      }
    }

    // Prevent cookies from being accessed through client-side script.
    setHTTPOnlyHeaderToSession(false, request, response);

    IEIDASSession eidasSession = controllerService.getSession();

    // Gets the attributes from Attribute Providers and validates mandatory
    // attributes.
    final Map<String, String> parameters = getHttpRequestParameters(request);
    parameters.put(EIDASParameters.ATTRIBUTE_LIST.toString(),
            attrList.toString());

    String relayState = parameters.get(EIDASParameters.RELAY_STATE.toString());

    if (eidasSession.containsKey(EIDASParameters.RELAY_STATE.toString())) {
      relayState = (String) eidasSession.get(
              EIDASParameters.RELAY_STATE.toString());
      getLogger().debug("Relay State ProxyService " + relayState);
    }

    final EIDASAuthnRequest authData =
            controllerService.getProxyService().processAPResponse(parameters, eidasSession);
    final IPersonalAttributeList localPal = authData.getPersonalAttributeList();

    // Setting internal variables, to be included by the Struts on the JSP
    getLogger().trace("setting internal variables");
    samlToken = new String(authData.getTokenSaml(), Charset.forName("UTF-8"));

    pal = new ArrayList<PersonalAttribute>();
    Boolean eidasAttributes=false;
    for(PersonalAttribute pa:localPal){
      //should use the iterator because it provides the items in their insert order
      EidasAttributesTypes eat = EIDASAttributes.getAttributeType(pa.getFullName());
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
    eidasSession.clear();

    String retVal;

    if (controllerService.isAskConsentValue()) {
      getLogger().trace("consent-value");
      retVal = NodeViewNames.EIDAS_SERVICE_CITIZEN_CONSENT.toString();
      getLogger().trace("Generate SAMLTokenFail");
      samlTokenFail =
              controllerService.getProxyService().generateSamlTokenFail(
                      authData,
                      EIDASErrors.CITIZEN_NO_CONSENT_MANDATORY,
                      getHttpRequestParameters(request).get(
                              EIDASParameters.REMOTE_ADDR.toString()));

    } else {
      getLogger().trace("no-consent-value");
      retVal = NodeViewNames.EIDAS_CONNECTOR_REDIRECT.toString();
    }

    request.setAttribute(NodeBeanNames.REDIRECT_URL.toString(), response.encodeRedirectURL(redirectUrl)); // Correct URl redirect cookie implementation
    request.setAttribute(NodeBeanNames.SAML_TOKEN.toString(), samlToken);
    request.setAttribute(NodeBeanNames.SAML_TOKEN_FAIL.toString(), samlTokenFail);
    request.setAttribute(NodeBeanNames.PAL.toString(), pal);
    request.setAttribute(NodeBeanNames.SP_ID.toString(), spId);
    request.setAttribute(NodeBeanNames.QAA_LEVEL.toString(),qaaLevel);
    if(eidasAttributes) {
      request.setAttribute(NodeBeanNames.LOA_VALUE.toString(), EidasAttributesUtil.getUserFriendlyLoa(authData.getEidasLoA()));
    }
    request.setAttribute(NodeBeanNames.RELAY_STATE.toString(), relayState);
    request.setAttribute(NodeBeanNames.EIDAS_ATTRIBUTES_PARAM.toString(), eidasAttributes);
    return retVal;
  }
}
