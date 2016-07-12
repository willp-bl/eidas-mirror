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

import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.exceptions.CPEPSException;
import eu.stork.peps.utils.PEPSErrorUtil;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles the exceptions thrown by C-PEPS.
 * 
 * @version $Revision: 1 $, $Date: 2014-10-21 $
 *
 */

public final class CPEPSExceptionHandlerServlet extends AbstractCPepsServlet {

  /**
   * Unique identifier.
   */
  private static final long serialVersionUID = -8806380050113511720L;

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(CPEPSExceptionHandlerServlet.class.getName());

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
    CPEPSException exception = null;
    String retVal = PepsViewNames.INTERNAL_ERROR.toString();
      try {
      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeaderToSession(false, request, response);

      // Obtaining the assertion consumer url from SPRING context
      IStorkSession storkSession = (IStorkSession) request.getSession().getAttribute("scopedTarget.cPepsSession");
      if(storkSession == null){
        LOG.debug("No cPepsSession found, are we working with MOA/MOCCA? -> take the sPepsSession");
        storkSession = (IStorkSession) request.getSession().getAttribute("scopedTarget.sPepsSession");
      }
      //Set the Exception
      exception = (CPEPSException) request.getAttribute("javax.servlet.error.exception");

      if (exception.getMessage() == null) {
        LOG.warn("An error occurred on PEPS! Couldn't get Exception message.");
      } else {
          String errorMessage=PEPSErrorUtil.resolveMessage(exception.getErrorMessage(), exception.getErrorCode(), request.getLocale());
          if(errorMessage!=null) {
              exception.setErrorMessage(errorMessage);
          }
        if (StringUtils.isBlank(exception.getSamlTokenFail())) {
            PEPSErrorUtil.prepareSamlResponseFail(request, exception, PEPSErrorUtil.ErrorSource.CPEPS);
          LOG.info("BUSINESS EXCEPTION : ", errorMessage);
        } else {
          LOG.info("BUSINESS EXCEPTION : ", exception.getMessage());
        }
      }

      // Setting internal variables
      request.setAttribute(PepsBeanNames.EXCEPTION.toString(), exception);
      retVal = PepsViewNames.PRESENT_ERROR.toString();
      if(storkSession != null) {
          if(!StringUtils.isBlank(exception.getSamlTokenFail()) && null!=storkSession.get(PEPSParameters.ERROR_REDIRECT_URL.toString())){
              retVal = PepsViewNames.SUBMIT_ERROR.toString();
          }
          if(storkSession.containsKey(PEPSParameters.ERROR_INTERCEPTOR_URL.toString())) {
              retVal =storkSession.get(PEPSParameters.ERROR_INTERCEPTOR_URL.toString()).toString();
              String redirectUrl=(String)storkSession.get(PEPSParameters.ERROR_REDIRECT_URL.toString());
              cleanSession(storkSession);
//              storkSession.clear();
              storkSession.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), redirectUrl);
          }else {
              request.setAttribute(PEPSParameters.ERROR_REDIRECT_URL.toString(),
                      storkSession.get(PEPSParameters.ERROR_REDIRECT_URL.toString()));
              storkSession.clear();
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

    private void cleanSession(IStorkSession storkSession){
        for(String paramName:PEPSParameters.getNames()){
            storkSession.remove(paramName);
        }
    }
}
