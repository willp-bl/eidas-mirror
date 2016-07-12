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

import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.auth.commons.exceptions.EidasNodeException;

import org.owasp.esapi.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Specific action that receives and stores the XML Response from Signature
 * Creator Module.
 *
 */
public final class SignatureCreatorResponseServlet extends AbstractSpecificServlet {

  private static final long serialVersionUID = -5384219662314510340L;

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(SignatureCreatorResponseServlet.class.getName());

  @Override
  protected Logger getLogger() {
    return LOG;
  }

    private void performRedirect(HttpServletRequest request, HttpServletResponse response, SignatureCreatorResponseBean sigCreatorResp){
        try {
            LOG.trace("sigCreatorResponse callbackURL: "+sigCreatorResp.getCallbackURL());
            response.sendRedirect(encodeURL(sigCreatorResp.getCallbackURL(),request,response));

        } catch (final IOException e) {
            LOG.info("ERROR : [execute] An errour occurs on the redirect from Signature Module.");
            throw new EidasNodeException(
                    "0",
                    "An error occur when trying to redirect from Signature Module:"+e);
        }

    }
  /**
   * Prepares the citizen to be redirected to the SignatureCreator Module.
   *
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    try {
      LOG.trace("execute SignatureCreatorResponseServlet");
      SignatureCreatorResponseBean sigCreatorResp = (SignatureCreatorResponseBean) getApplicationContext().getBean("springManagedSigCreatorResp");

      // Prevent cookies from being accessed through client-side script.
      setHTTPOnlyHeader(request, response);

      // obtain XML response from MOCCA
      final String createXMLSignatureResponse =
              request.getParameter(EIDASParameters.XML_RESPONSE.toString());

      // store response to session
      if ( !StringUtilities.isEmpty(createXMLSignatureResponse)) {
        final List<String> values = new ArrayList<String>(1);
        values.add(createXMLSignatureResponse);
        sigCreatorResp.getSession().put(EIDASParameters.SIGNATURE_RESPONSE.toString(), values);
      } else {
        LOG.info("ERROR : [execute] No createXMLSignatureResponse found!");
      }

      performRedirect(request, response, sigCreatorResp);

    }catch (AbstractEIDASException e){
        LOG.info("ERROR : ", e.getErrorMessage());
        LOG.debug("ERROR : ", e);
        throw e;
    }
  }

}