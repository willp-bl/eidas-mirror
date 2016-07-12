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
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Specific action that handles the incoming response from the Identity
 * Provider.
 */
public final class SpecificIdPResponseServlet extends AbstractSpecificServlet {


    private static final long serialVersionUID = -4965943270621931284L;

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SpecificIdPResponseServlet.class.getName());

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    /**
     * This action is executed upon returning from the IdP. Validates the response
     * and stores the login credentials.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        /**
         * SAML token.
         */
        String samlResponse = "";

        /**
         * Personal attribute list.
         */
        IPersonalAttributeList attrList = null;

        /**
         * Authenticated user.
         */
        String username = "";

        /**
         * Error code.
         */
        String errorCode = "";

        /**
         * Error subordinate code.
         */
        String subCode = "";

        /**
         * Error message.
         */
        String errorMessage = "";

        try {
            LOG.debug("**** EXECUTE : SpecificIdPResponseServlet ****");

            SpecificIdPBean controllerService = (SpecificIdPBean) getApplicationContext().getBean("springManagedSpecificIdPResponse");

            username = request.getParameter(EIDASParameters.USERNAME.toString());
            samlResponse = request.getParameter(EIDASParameters.SAML_RESPONSE.toString());


            EIDASUtil.validateParameter(
                    SpecificIdPResponseServlet.class.getCanonicalName(),
                    EIDASParameters.SAML_RESPONSE.toString(), samlResponse,
                    EIDASErrors.IDP_SAML_RESPONSE);
            final EIDASAuthnResponse authnResponse =
                    controllerService.getSpecificNode().processAuthenticationResponse(
                            EIDASUtil.decodeSAMLToken(samlResponse), controllerService.getSession());

            validateResponse(authnResponse, controllerService);

            if (authnResponse != null
                    && !authnResponse.getStatusCode().equals(EIDASStatusCode.SUCCESS_URI.toString())) {
                errorCode = authnResponse.getStatusCode();
                LOG.debug("[execute] Message from IdP with status code: " + errorCode);
                subCode = authnResponse.getSubStatusCode();
                if (authnResponse.getMessage() == null) {
                    errorMessage = errorCode;
                } else {
                    errorMessage = authnResponse.getMessage();
                }
                request.setAttribute(EIDASParameters.ATTRIBUTE_LIST.toString(), attrList);
                request.setAttribute(EIDASParameters.ERROR_MESSAGE.toString(), errorMessage);
                request.setAttribute(EIDASParameters.ERROR_CODE.toString(), errorCode);
                request.setAttribute(EIDASParameters.ERROR_SUBCODE.toString(), subCode);

                RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL
                        (SpecificViewNames.IDP_RESPONSE.toString()));
                dispatcher.forward(request, response);

                return;

            }

            EIDASUtil.validateParameter(
                    SpecificIdPResponseServlet.class.getCanonicalName(),
                    EIDASParameters.USERNAME.toString(), username);
            controllerService.getSession().put(EIDASParameters.USERNAME.toString(), username);
            if (((EIDASAuthnRequest) controllerService.getSession().get(EIDASParameters.AUTH_REQUEST.toString())) != null) {
                final IPersonalAttributeList sessionPal = ((EIDASAuthnRequest) controllerService.getSession().get(EIDASParameters.AUTH_REQUEST.toString())).getPersonalAttributeList();
                // validate attrList
                if (authnResponse != null && authnResponse.getPersonalAttributeList() != null) {
                    if (!controllerService.getSpecificNode().comparePersonalAttributeLists(sessionPal, authnResponse.getPersonalAttributeList())) {
                        errorCode = EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorCode());
                        errorMessage = EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorMessage());
                    } else {
                        attrList = authnResponse.getPersonalAttributeList();
                    }
                }
            } else {
                errorCode = EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorCode());
                errorMessage = EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorMessage());
            }
            request.setAttribute(EIDASParameters.ATTRIBUTE_LIST.toString(), attrList);
            if(authnResponse!=null) {
                request.setAttribute(EIDASParameters.EIDAS_SERVICE_LOA.toString(), authnResponse.getAssuranceLevel());
            }
            request.setAttribute(EIDASParameters.ERROR_MESSAGE.toString(), errorMessage);
            request.setAttribute(EIDASParameters.ERROR_CODE.toString(), errorCode);

            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL
                    (SpecificViewNames.IDP_RESPONSE.toString()));
            dispatcher.forward(request, response);
        } catch (ServletException e) {
            LOG.info("ERROR : ", e.getMessage());
            LOG.debug("ERROR : ", e);
            throw e;
        } catch (IOException e) {
            LOG.info("ERROR : ", e.getMessage());
            LOG.debug("ERROR : ", e);
            throw e;
        }
    }


    /**
     * Validates a given {@link eu.eidas.auth.commons.EIDASAuthnResponse}.
     *
     * @param authnResponse     The {@link eu.eidas.auth.commons.EIDASAuthnResponse} to validate.
     * @param controllerService
     */
    private void validateResponse(final EIDASAuthnResponse authnResponse, SpecificIdPBean controllerService) {
        if (controllerService.getSession() != null) {
            final String sessionIdRequest = authnResponse.getInResponseTo();
            final String sessionIdActual = (String) controllerService.getSession().get(EIDASParameters.SAML_IN_RESPONSE_TO_IDP.toString());
            final String audienceRestriction = authnResponse.getAudienceRestriction();
            final String issuer = (String) controllerService.getSession().get(EIDASParameters.ISSUER_IDP.toString());
            if (sessionIdActual == null || issuer == null) {
                LOG.info("Clearing session - following parameter is null : "
                        + (sessionIdActual != null ? "getSession().get(inResponseTo.idp)" : "")
                        + (issuer != null ? "getSession().get(samlIssuer.idp)" : ""));
                controllerService.getSession().clear();
            } else {
                if (sessionIdRequest != null
                        && !sessionIdActual.equals(sessionIdRequest)
                        && audienceRestriction != null && !issuer.equals(audienceRestriction)) {
                    LOG.info("ERROR : [SpecificIdPResponseAction] Invalid request session id");
                    throw new InvalidSessionEIDASException(
                            EIDASUtil.getConfig(EIDASErrors.SESSION.errorCode()),
                            EIDASUtil.getConfig(EIDASErrors.SESSION.errorMessage()));
                }
            }
        }
    }
}
