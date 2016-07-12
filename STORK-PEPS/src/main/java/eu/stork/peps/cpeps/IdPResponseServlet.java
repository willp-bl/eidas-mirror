/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations 
 * under the License.
 */
package eu.stork.peps.cpeps;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.exceptions.InvalidSessionPEPSException;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.utils.PropertiesUtil;
import org.owasp.esapi.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Action that handles the incoming response from the Identity Provider.
 * 
 */
public final class IdPResponseServlet extends AbstractCPepsServlet {


  private static final long serialVersionUID = 8306593771657820731L;
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(IdPResponseServlet.class.getName());

  @Override
  protected Logger getLogger() {
    return LOG;
  }

  /**
   * Validates the incoming parameters and executes the method
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    /**
     * Attribute list returned by the IdP.
     */
    IPersonalAttributeList attrList;

    /**
     * Error code returned by the IdP (only in case of error).
     */
    String errorCode;

    /**
     * Error subordinate code (only in case of error).
     */
    String subCode;

    /**
     * Error message returned by the IdP (only in case of error).
     */
    String errorMessage;

    try{

      attrList = (IPersonalAttributeList) request.getAttribute(PEPSParameters.ATTRIBUTE_LIST.toString());
      errorCode = (String) request.getAttribute(PEPSParameters.ERROR_CODE.toString());
      subCode = (String) request.getAttribute(PEPSParameters.ERROR_SUBCODE.toString());
      errorMessage = (String) request.getAttribute(PEPSParameters.ERROR_MESSAGE.toString());


      // Obtaining the assertion consumer url from SPRING context
      CPepsControllerService controllerService = (CPepsControllerService) getApplicationContext().getBean(PepsBeanNames.C_PEPS_CONTROLLER.toString());

      // Validate if the session has the required attributes.
      synchronized (controllerService.getSession()) {
        LOG.debug("Session content " + controllerService.getSession());
        if (controllerService.getSession().get(PEPSParameters.AUTH_REQUEST.toString()) == null
                || controllerService.getSession().get(PEPSParameters.REMOTE_ADDR.toString()) == null) {
          LOG.info("BUSINESS EXCEPTION : Session is null or invalid!");
          throw new InvalidSessionPEPSException(
                  PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorCode()),
                  PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorMessage()));
        }
      }
      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeaderToSession(false, request, response);

      final Map<String, String> parameters = getHttpRequestParameters(request);

      // If the IdP doesn't sends any error then we must validate some
      // parameters.
      if (StringUtilities.isEmpty(errorCode)) {
        // Validating Struts' attrList "chain" parameter
        PEPSUtil.validateParameter(IdPResponseServlet.class.getCanonicalName(),
                PEPSErrors.INVALID_ATTRIBUTE_LIST.toString(), attrList);
        parameters.put(PEPSParameters.ATTRIBUTE_LIST.toString(),
                attrList.toString());
      } else {
        parameters.put(PEPSParameters.ERROR_CODE.toString(), errorCode);
        if (!StringUtilities.isEmpty(subCode)) {
          parameters.put(PEPSParameters.ERROR_SUBCODE.toString(), subCode);
        }
        parameters.put(PEPSParameters.ERROR_MESSAGE.toString(), errorMessage);
      }

      controllerService.getCpepsService().processIdPResponse(parameters, controllerService.getSession());
      request.setAttribute(PEPSParameters.ATTRIBUTE_LIST.toString(), attrList);

      LOG.debug("[APSelector]: "+PropertiesUtil.getProperty(PepsViewNames.AP_SELECTOR.toString()));

      RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(PropertiesUtil.getProperty(PepsViewNames.AP_SELECTOR.toString()));
      dispatcher.forward(request,response);
    }catch(ServletException e){
      LOG.info(e.toString());
      throw e;

    }catch(IOException e) {
      LOG.info(e.toString());
      throw e;
    }
  }
}
