/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software distributed 
 * under the License is distributed on an "AS IS" BASIS,  WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the 
 * specific language governing permissions and    limitations under the License.
 */
package eu.eidas.node;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

/**
 * This Specific action is responsible for the citizen authentication.
 *
 */
public final class CitizenAuthenticationServlet extends AbstractSpecificServlet {


  private static final long serialVersionUID = -6029084258875603184L;
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(CitizenAuthenticationServlet.class.getName());


  @Override
  protected Logger getLogger() {
    return LOG;
  }
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }

  /**
   * Prepares the citizen to be redirected to the IdP.
   *
   * @return SpecificViewNames.IDP_REDIRECT.toString() if the citizen is going to
   *         be authenticated via external IdP,
   *         EidasParameters.INTERNAL_AUTH.toString() if the citizen is going to
   *         be authenticated via internal IdP.
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    /**
     * Personal attribute list.
     */
    IPersonalAttributeList attrList;

    /**
     * URL of ProxyService IdP response handler.
     */
    String callbackURL;

    // used by jsp

    /**
     * SAML token.
     */
    String samlToken;

    try{
      CitizenAuthenticationBean citizenAuthentication = (CitizenAuthenticationBean) getApplicationContext().getBean("springManagedCitizenAuthentication");

      callbackURL = response.encodeURL((String) request.getAttribute(SpecificParameterNames.CALLBACK_URL.toString()));
      LOG.debug("Setting callbackURL: " + callbackURL);
      attrList = (IPersonalAttributeList) request.getAttribute(EIDASParameters.ATTRIBUTE_LIST.toString());

      LOG.debug("Session content " + citizenAuthentication.getSession());
      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeader(request, response);

      // build parameter list
      final Map<String, Object> parameters = getHttpRequestParameters(request);

      if (citizenAuthentication.isExternalAuth()) {

        EIDASUtil.validateParameter(
                CitizenAuthenticationServlet.class.getCanonicalName(),
                EIDASParameters.IDP_URL.toString(), citizenAuthentication.getIdpUrl());
        EIDASUtil.validateParameter(
                CitizenAuthenticationServlet.class.getCanonicalName(),
                EIDASParameters.EIDAS_SERVICE_CALLBACK.toString(), callbackURL);
        parameters.put(EIDASParameters.IDP_URL.toString(), citizenAuthentication.getIdpUrl());
        parameters.put(EIDASParameters.EIDAS_SERVICE_CALLBACK.toString(), callbackURL);

        final EIDASAuthnRequest authRequest =
                (EIDASAuthnRequest) citizenAuthentication.getSession().get(
                        EIDASParameters.AUTH_REQUEST.toString());
        parameters.put(EIDASParameters.QAALEVEL.toString(), authRequest.getQaa());
          if(EIDASAuthnRequest.BINDING_REDIRECT.equals(authRequest.getBinding())) {
              request.setAttribute(EIDASParameters.BINDING.toString(), EIDASAuthnRequest.BINDING_REDIRECT);
          }else {
              request.setAttribute(EIDASParameters.BINDING.toString(), EIDASAuthnRequest.BINDING_POST);
          }
        parameters.put(EIDASParameters.EIDAS_SERVICE_LOA.toString(), authRequest.getEidasLoA());
        parameters.put(EIDASParameters.EIDAS_NAMEID_FORMAT.toString(), authRequest.getEidasNameidFormat());
        final byte[] samlTokenBytes =
                citizenAuthentication.getSpecAuthenticationNode().prepareCitizenAuthentication(attrList,
                        parameters, getHttpRequestAttributesHeaders(request), citizenAuthentication.getSession());
        samlToken = EIDASUtil.encodeSAMLToken(samlTokenBytes);

        request.setAttribute(SpecificParameterNames.SAML_TOKEN.toString(), samlToken);
        request.setAttribute(SpecificParameterNames.IDP_URL.toString(), citizenAuthentication.getIdpUrl());
        request.setAttribute(EIDASParameters.REQUEST_FORMAT.toString(), authRequest.getMessageFormatName());
        LOG.trace("[execute] external-authentication");

        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL
                (SpecificViewNames.IDP_REDIRECT.toString()));
        dispatcher.forward(request,response);
        return;

      } else {
        attrList = citizenAuthentication.getSpecAuthenticationNode().authenticateCitizen(attrList,
                        parameters, getHttpRequestAttributesHeaders(request));

        // this part is just for reference purposes, since we use the
        // username
        // to call the AP -- you might change this as you please.
        final String username = "jose";
        citizenAuthentication.getSession().put(EIDASParameters.USERNAME.toString(), username);

        request.setAttribute(EIDASParameters.ATTRIBUTE_LIST.toString(), attrList);

        LOG.trace("[execute] internal-authentication");

        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL(SpecificViewNames
                .IDP_RESPONSE.toString()));
        dispatcher.forward(request,response);

      }
    }catch (ServletException e){
      LOG.info("ERROR : ", e.getMessage());
      LOG.debug("ERROR : ", e);
      throw e;
    }catch (IOException e){
      LOG.info("ERROR : ", e.getMessage());
      LOG.debug("ERROR : ", e);
      throw e;
    }catch (AbstractEIDASException e){
      LOG.info("ERROR : ", e.getErrorMessage());
      LOG.debug("ERROR : ", e);
      throw e;
    }
  }
}
