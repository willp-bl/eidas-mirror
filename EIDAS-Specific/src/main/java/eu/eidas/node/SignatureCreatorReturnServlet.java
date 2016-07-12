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

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Specific action that receives the control from Signature Creator Module.
 *
 */
public final class SignatureCreatorReturnServlet extends AbstractSpecificServlet {

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(SignatureCreatorReturnServlet.class.getName());

  @Override
  protected Logger getLogger() {
    return LOG;
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    handleRequest(request, response);
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    handleRequest(request, response);
  }
  /**
   * Sets the signed doc after invoking the SignatureCreator module and passes
   * control back to the Specific Node.
   *
   */
  protected void handleRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    // chained attributes
    /**
     * Personal attribute list.
     */
    PersonalAttributeList attrList;

    try {
      LOG.debug("execute SignatureCreatorReturnServlet");
      SignatureCreatorReturnBean sigCreatorReturn = (SignatureCreatorReturnBean) getApplicationContext().getBean("springManagedSigCreatorReturn");

      attrList = (PersonalAttributeList) request.getAttribute(EIDASParameters.ATTRIBUTE_LIST.toString());

      if (sigCreatorReturn.getSession() == null) {
        LOG.info("ERROR : [execute] Session is null");
        throw new InvalidSessionEIDASException(EIDASUtil
                .getConfig(EIDASErrors.INVALID_SESSION.errorCode()), EIDASUtil
                .getConfig(EIDASErrors.INVALID_SESSION.errorMessage()));
      }

      final IPersonalAttributeList pal =
              (PersonalAttributeList) sigCreatorReturn.getSession().get(EIDASParameters.ATTRIBUTE_LIST
                      .toString());
      if (pal != null) {
        if (pal.containsKey(sigCreatorReturn.getAttribute())
                && sigCreatorReturn.getSession()
                .containsKey(EIDASParameters.SIGNATURE_RESPONSE.toString())) {
          if (sigCreatorReturn.getSession().get(EIDASParameters.SIGNATURE_RESPONSE.toString()) instanceof ArrayList<?>) {
            LOG.debug("[execute] Session's signatureResponse is OK");
            final List<String> values =
                    (ArrayList<String>) sigCreatorReturn.getSession()
                            .get(EIDASParameters.SIGNATURE_RESPONSE.toString());
            final PersonalAttribute pAttr = pal.get(sigCreatorReturn.getAttribute());
            pAttr.setValue(values);
            pAttr.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
            pal.put(sigCreatorReturn.getAttribute(), pAttr);
            final EIDASAuthnRequest authData =
                    (EIDASAuthnRequest) sigCreatorReturn.getSession().get(EIDASParameters.AUTH_REQUEST
                            .toString());
            final IPersonalAttributeList sessionPal =
                    authData.getPersonalAttributeList();
            sessionPal.put(sigCreatorReturn.getAttribute(), pAttr);
            authData.setPersonalAttributeList(sessionPal);
            sigCreatorReturn.getSession().put(EIDASParameters.AUTH_REQUEST.toString(), authData);
            attrList = (PersonalAttributeList) pal;
          } else {
            LOG.info("ERROR : [execute] Session's signatureResponse isn't a ArrayList: "
                    + sigCreatorReturn.getSession().get(EIDASParameters.SIGNATURE_RESPONSE.toString()));
          }
        }
      } else {
        LOG.info("ERROR : [execute] Session's Personal Attribute List is null");
      }

      sigCreatorReturn.getSession().remove(EIDASParameters.ATTRIBUTE_LIST.toString());

      request.setAttribute(EIDASParameters.ATTRIBUTE_LIST.toString(), attrList);
      RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL
              (SpecificViewNames.AP_RESPONSE.toString()));
      dispatcher.forward(request,response);

    }catch (AbstractEIDASException e){
      LOG.info("ERROR : ", e.getErrorMessage());
      LOG.debug("ERROR : ", e);
      throw e;
    }
  }
}
