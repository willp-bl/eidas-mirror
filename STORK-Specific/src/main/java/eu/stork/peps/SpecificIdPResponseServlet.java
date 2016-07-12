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

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.InvalidSessionPEPSException;
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

            username = request.getParameter(PEPSParameters.USERNAME.toString());
            samlResponse = request.getParameter(PEPSParameters.SAML_RESPONSE.toString());


            PEPSUtil.validateParameter(
                    SpecificIdPResponseServlet.class.getCanonicalName(),
                    PEPSParameters.SAML_RESPONSE.toString(), samlResponse,
                    PEPSErrors.IDP_SAML_RESPONSE);
            final STORKAuthnResponse authnResponse =
                    controllerService.getSpecificPeps().processAuthenticationResponse(
                            PEPSUtil.decodeSAMLToken(samlResponse), controllerService.getSession());

            validateResponse(authnResponse, controllerService);

            if (authnResponse != null
                    && !authnResponse.getStatusCode().equals(STORKStatusCode.SUCCESS_URI.toString())) {
                errorCode = authnResponse.getStatusCode();
                LOG.debug("[execute] Message from IdP with status code: " + errorCode);
                subCode = authnResponse.getSubStatusCode();
                if (authnResponse.getMessage() == null) {
                    errorMessage = errorCode;
                } else {
                    errorMessage = authnResponse.getMessage();
                }
                request.setAttribute(PEPSParameters.ATTRIBUTE_LIST.toString(), attrList);
                request.setAttribute(PEPSParameters.ERROR_MESSAGE.toString(), errorMessage);
                request.setAttribute(PEPSParameters.ERROR_CODE.toString(), errorCode);
                request.setAttribute(PEPSParameters.ERROR_SUBCODE.toString(), subCode);

                RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(response.encodeURL
                        (SpecificViewNames.IDP_RESPONSE.toString()));
                dispatcher.forward(request, response);

                return;

            }

            PEPSUtil.validateParameter(
                    SpecificIdPResponseServlet.class.getCanonicalName(),
                    PEPSParameters.USERNAME.toString(), username);
            controllerService.getSession().put(PEPSParameters.USERNAME.toString(), username);
            if (((STORKAuthnRequest) controllerService.getSession().get(PEPSParameters.AUTH_REQUEST.toString())) != null) {
                final IPersonalAttributeList sessionPal = ((STORKAuthnRequest) controllerService.getSession().get(PEPSParameters.AUTH_REQUEST.toString())).getPersonalAttributeList();
                // validate attrList
                if (authnResponse != null && authnResponse.getPersonalAttributeList() != null) {
                    if (!controllerService.getSpecificPeps().comparePersonalAttributeLists(sessionPal, authnResponse.getPersonalAttributeList())) {
                        errorCode = PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorCode());
                        errorMessage = PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorMessage());
                    } else {
                        attrList = authnResponse.getPersonalAttributeList();
                    }
                }
            } else {
                errorCode = PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorCode());
                errorMessage = PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorMessage());
            }
            request.setAttribute(PEPSParameters.ATTRIBUTE_LIST.toString(), attrList);
            request.setAttribute(PEPSParameters.ERROR_MESSAGE.toString(), errorMessage);
            request.setAttribute(PEPSParameters.ERROR_CODE.toString(), errorCode);

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
     * Validates a given {@link eu.stork.peps.auth.commons.STORKAuthnResponse}.
     *
     * @param authnResponse     The {@link eu.stork.peps.auth.commons.STORKAuthnResponse} to validate.
     * @param controllerService
     */
    private void validateResponse(final STORKAuthnResponse authnResponse, SpecificIdPBean controllerService) {
        if (controllerService.getSession() != null) {
            final String sessionIdRequest = authnResponse.getInResponseTo();
            final String sessionIdActual = (String) controllerService.getSession().get(PEPSParameters.SAML_IN_RESPONSE_TO_IDP.toString());
            final String audienceRestriction = authnResponse.getAudienceRestriction();
            final String issuer = (String) controllerService.getSession().get(PEPSParameters.ISSUER_IDP.toString());
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
                    throw new InvalidSessionPEPSException(
                            PEPSUtil.getConfig(PEPSErrors.SESSION.errorCode()),
                            PEPSUtil.getConfig(PEPSErrors.SESSION.errorMessage()));
                }
            }
        }
    }
}
