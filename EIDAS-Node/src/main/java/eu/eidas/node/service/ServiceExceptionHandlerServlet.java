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
package eu.eidas.node.service;

import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;
import eu.eidas.node.utils.EidasNodeErrorUtil;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Handles the exceptions thrown by the ProxyService.
 * 
 * @version $Revision: 1 $, $Date: 2014-10-21 $
 *
 */

public final class ServiceExceptionHandlerServlet extends AbstractServiceServlet {

  /**
   * Unique identifier.
   */
  private static final long serialVersionUID = -8806380050113511720L;

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(ServiceExceptionHandlerServlet.class.getName());

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
    String retVal = NodeViewNames.INTERNAL_ERROR.toString();
      try {
      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeaderToSession(false, request, response);

      // Obtaining the assertion consumer url from SPRING context
      IEIDASSession eidasSession = (IEIDASSession) request.getSession().getAttribute("scopedTarget.serviceSession");
      if(eidasSession == null){
        LOG.debug("No ServiceSession found, are we working with MOA/MOCCA? -> take the ConnectorSession");
        eidasSession = (IEIDASSession) request.getSession().getAttribute("scopedTarget.connectorSession");
      }
      //Set the Exception
      exception = (AbstractEIDASException) request.getAttribute("javax.servlet.error.exception");

      if (exception.getMessage() == null) {
        LOG.warn("An error occurred on EidasNode! Couldn't get Exception message.");
      } else {
          String errorMessage=EidasNodeErrorUtil.resolveMessage(exception.getErrorMessage(), exception.getErrorCode(), request.getLocale());
          if(errorMessage!=null) {
              exception.setErrorMessage(errorMessage);
          }
        if (StringUtils.isBlank(exception.getSamlTokenFail())) {
            EidasNodeErrorUtil.prepareSamlResponseFail(request, exception, EidasNodeErrorUtil.ErrorSource.PROXYSERVICE);
          LOG.info("BUSINESS EXCEPTION : ", errorMessage);
        } else {
          LOG.info("BUSINESS EXCEPTION : ", exception.getMessage());
        }
      }

      // Setting internal variables
      request.setAttribute(NodeBeanNames.EXCEPTION.toString(), exception);
      retVal = NodeViewNames.PRESENT_ERROR.toString();
      if(eidasSession != null) {
          if(!StringUtils.isBlank(exception.getSamlTokenFail()) && null!=eidasSession.get(EIDASParameters.ERROR_REDIRECT_URL.toString())){
              retVal = NodeViewNames.SUBMIT_ERROR.toString();
          }
          if(eidasSession.containsKey(EIDASParameters.ERROR_INTERCEPTOR_URL.toString())) {
              retVal =eidasSession.get(EIDASParameters.ERROR_INTERCEPTOR_URL.toString()).toString();
              String redirectUrl=(String)eidasSession.get(EIDASParameters.ERROR_REDIRECT_URL.toString());
              cleanSession(eidasSession);
              eidasSession.put(EIDASParameters.ERROR_REDIRECT_URL.toString(), redirectUrl);
          }else {
              request.setAttribute(EIDASParameters.ERROR_REDIRECT_URL.toString(),
                      eidasSession.get(EIDASParameters.ERROR_REDIRECT_URL.toString()));
              eidasSession.clear();
          }
      }


    }catch(Exception e){
      LOG.info("BUSINESS EXCEPTION : {}", e);
    }
    //Forward to error page
    RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(retVal);
    response.setStatus(HttpServletResponse.SC_OK);
    dispatcher.forward(request, response);
  }

    private void cleanSession(IEIDASSession eidasSession){
        for(String paramName:EIDASParameters.getNames()){
            eidasSession.remove(paramName);
        }
    }
}
