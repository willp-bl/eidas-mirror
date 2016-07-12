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
package eu.stork.peps;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.exceptions.AbstractPEPSException;
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
   *         PEPSParameters.INTERNAL_AUTH.toString() if the citizen is going to
   *         be authenticated via internal IdP.
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    /**
     * Personal attribute list.
     */
    IPersonalAttributeList attrList;

    /**
     * URL of C-PEPS IdP response handler.
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
      attrList = (IPersonalAttributeList) request.getAttribute(PEPSParameters.ATTRIBUTE_LIST.toString());

      LOG.debug("Session content " + citizenAuthentication.getSession());
      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeader(request, response);

      // build parameter list
      final Map<String, Object> parameters = getHttpRequestParameters(request);

      if (citizenAuthentication.isExternalAuth()) {

        PEPSUtil.validateParameter(
                CitizenAuthenticationServlet.class.getCanonicalName(),
                PEPSParameters.IDP_URL.toString(), citizenAuthentication.getIdpUrl());
        PEPSUtil.validateParameter(
                CitizenAuthenticationServlet.class.getCanonicalName(),
                PEPSParameters.CPEPS_CALLBACK.toString(), callbackURL);
        parameters.put(PEPSParameters.IDP_URL.toString(), citizenAuthentication.getIdpUrl());
        parameters.put(PEPSParameters.CPEPS_CALLBACK.toString(), callbackURL);

        final STORKAuthnRequest authRequest =
                (STORKAuthnRequest) citizenAuthentication.getSession().get(
                        PEPSParameters.AUTH_REQUEST.toString());
        parameters.put(PEPSParameters.QAALEVEL.toString(), authRequest.getQaa());
          if(STORKAuthnRequest.BINDING_REDIRECT.equals(authRequest.getBinding())) {
              request.setAttribute(PEPSParameters.BINDING.toString(), STORKAuthnRequest.BINDING_REDIRECT);
          }else {
              request.setAttribute(PEPSParameters.BINDING.toString(), STORKAuthnRequest.BINDING_POST);
          }
        parameters.put(PEPSParameters.EIDAS_SERVICE_LOA.toString(), authRequest.getEidasLoA());
        parameters.put(PEPSParameters.EIDAS_NAMEID_FORMAT.toString(), authRequest.getEidasNameidFormat());
        final byte[] samlTokenBytes =
                citizenAuthentication.getSpecAuthenticationPeps().prepareCitizenAuthentication(attrList,
                        parameters, getHttpRequestAttributesHeaders(request), citizenAuthentication.getSession());
        samlToken = PEPSUtil.encodeSAMLToken(samlTokenBytes);

        request.setAttribute(SpecificParameterNames.SAML_TOKEN.toString(), samlToken);
        request.setAttribute(SpecificParameterNames.IDP_URL.toString(), citizenAuthentication.getIdpUrl());
        LOG.trace("[execute] external-authentication");

        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL
                (SpecificViewNames.IDP_REDIRECT.toString()));
        dispatcher.forward(request,response);
        return;

      } else {
        attrList = citizenAuthentication.getSpecAuthenticationPeps().authenticateCitizen(attrList,
                        parameters, getHttpRequestAttributesHeaders(request));

        // this part is just for reference purposes, since we use the
        // username
        // to call the AP -- you might change this as you please.
        final String username = "jose";
        citizenAuthentication.getSession().put(PEPSParameters.USERNAME.toString(), username);

        request.setAttribute(PEPSParameters.ATTRIBUTE_LIST.toString(), attrList);

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
    }catch (AbstractPEPSException e){
      LOG.info("ERROR : ", e.getErrorMessage());
      LOG.debug("ERROR : ", e);
      throw e;
    }
  }
}
