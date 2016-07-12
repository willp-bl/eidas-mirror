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
package eu.eidas.node.connector;

import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.node.AbstractNodeServlet;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;
import eu.eidas.node.utils.EidasNodeErrorUtil;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.ResourceBundleMessageSource;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Handles the exceptions thrown by Connector.
 * 
 * @version $Revision: 1 $, $Date: 2014-10-21 $
 *
 */

public final class ConnectorExceptionHandlerServlet extends AbstractNodeServlet {

  /**
   * Unique identifier.
   */
  private static final long serialVersionUID = -8806380050113511720L;

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(ConnectorExceptionHandlerServlet.class.getName());

  @Override
  protected Logger getLogger() {
    return LOG;
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    handleError(request, response);
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    handleError(request, response);
  }

  /**
   * Prepares exception redirection, or if no information is available to
   * redirect, prepares the exception to be displayed. Also, clears the current
   * session object, if not needed.
   *
   * @return {ERROR} if there is no URL to return to,
   *         {SUCCESS} otherwise.
   *
   */
  private void handleError(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    /**
     * Current exception.
     */
    AbstractEIDASException exception = null;

    /**
     * URL to redirect the citizen to.
     */
    String errorRedirectUrl = null;

    String retVal = NodeViewNames.INTERCEPTOR_ERROR.toString();

    try {
      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeaderToSession(false, request, response);

      // Obtaining the assertion consumer url from SPRING context
      IEIDASSession eidasSession = (IEIDASSession) request.getSession().getAttribute("scopedTarget.connectorSession");
      if(eidasSession == null){
            LOG.debug("No ConnectorSession found, looking for a ServiceSession");
            eidasSession = (IEIDASSession) request.getSession().getAttribute("scopedTarget.serviceSession");
      }
      //Set the Exception
      exception = (AbstractEIDASException) request.getAttribute("javax.servlet.error.exception");
      prepareErrorMessage(exception, request);
      errorRedirectUrl = prepareSession(eidasSession, exception, request);
      request.setAttribute(NodeBeanNames.EXCEPTION.toString(), exception);

      retVal = NodeViewNames.ERROR.toString();
      if(!StringUtils.isBlank(exception.getSamlTokenFail()) && null!=eidasSession.get(EIDASParameters.ERROR_REDIRECT_URL.toString())){
        retVal = NodeViewNames.SUBMIT_ERROR.toString();
      }

      if (errorRedirectUrl == null
              || exception.getSamlTokenFail() == null) {
        LOG.debug("BUSINESS EXCEPTION - null redirectUrl");
        retVal = NodeViewNames.INTERCEPTOR_ERROR.toString();
      } else {
        LOG.debug("ErrorRedirectUrl: " + errorRedirectUrl);
      }

    }catch(Exception e){
      LOG.info("BUSINESS EXCEPTION : error in exception handler: {}",e.getMessage());
      LOG.debug("BUSINESS EXCEPTION : error in exception handler: {}",e);
    }
    //Forward to error page
    RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(retVal);
    response.setStatus(HttpServletResponse.SC_OK);
    dispatcher.forward(request,response);
  }

  private void prepareErrorMessage(AbstractEIDASException exception,HttpServletRequest request){
    if (exception.getMessage() == null) {
      LOG.info("BUSINESS EXCEPTION : An error occurred on EidasNode! Couldn't get Exception message.");
    } else {
      if (StringUtils.isBlank(exception.getSamlTokenFail())) {
        ResourceBundleMessageSource msgResource = (ResourceBundleMessageSource) getApplicationContext().
                getBean(NodeBeanNames.SYSADMIN_MESSAGE_RESOURCES.toString());
        final String errorMessage = msgResource.getMessage(exception.getErrorMessage(), new Object[] {
                exception.getErrorCode() }, request.getLocale());
        exception.setErrorMessage(errorMessage);
        EidasNodeErrorUtil.prepareSamlResponseFail(request, exception, EidasNodeErrorUtil.ErrorSource.CONNECTOR);
        LOG.info("BUSINESS EXCEPTION : ",errorMessage);
      } else {
        LOG.info("BUSINESS EXCEPTION : ", exception.getMessage());
      }
    }

  }

  private String prepareSession(IEIDASSession eidasSession,AbstractEIDASException exception,HttpServletRequest request){
    String errorRedirectUrl = null;
    if (eidasSession != null) {
      // Setting internal variables
      LOG.trace("Setting internal variables");
      if (eidasSession.containsKey(EIDASParameters.ERROR_REDIRECT_URL.toString())) {
        errorRedirectUrl = (String) eidasSession.get(EIDASParameters.ERROR_REDIRECT_URL.toString());
        request.setAttribute(EIDASParameters.ERROR_REDIRECT_URL.toString(), errorRedirectUrl);
      }

      // Validating the optional HTTP Parameter relayState.
      final String relayStateCons = EIDASParameters.RELAY_STATE.toString();
      if (eidasSession.containsKey(relayStateCons)) {
        request.setAttribute(NodeBeanNames.RELAY_STATE.toString(), eidasSession.get(relayStateCons));
      }
      if (!(exception instanceof InvalidSessionEIDASException)) {
        LOG.debug("Clearing session");
        eidasSession.clear();
        // If it's an InvalidSessionException the session will not
        // be cleared because it's going to be used by another request
      }
    }
    return errorRedirectUrl;
  }
}
