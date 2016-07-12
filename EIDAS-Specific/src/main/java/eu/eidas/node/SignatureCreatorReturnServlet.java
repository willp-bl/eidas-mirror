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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.EidasErrors;
import eu.eidas.auth.commons.EidasParameterKeys;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.exceptions.AbstractEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.auth.commons.protocol.eidas.IEidasAuthenticationRequest;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequest;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.core.ProtocolProcessorI;

/**
 * Specific action that receives the control from Signature Creator Module.
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
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        handleRequest(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        handleRequest(request, response);
    }

    /**
     * Sets the signed doc after invoking the SignatureCreator module and passes control back to the Specific Node.
     */
    protected void handleRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // chained attributes
        /**
         * Personal attribute list.
         */
        PersonalAttributeList attrList;

        try {
            LOG.debug("execute SignatureCreatorReturnServlet");
            SignatureCreatorReturnBean sigCreatorReturn =
                    (SignatureCreatorReturnBean) getApplicationContext().getBean("springManagedSigCreatorReturn");

            attrList = (PersonalAttributeList) request.getAttribute(EidasParameterKeys.ATTRIBUTE_LIST.toString());

            if (sigCreatorReturn.getSession() == null) {
                LOG.info("ERROR : [execute] Session is null");
                throw new InvalidSessionEIDASException(EidasErrors.get(EidasErrorKey.INVALID_SESSION.errorCode()),
                                                       EidasErrors.get(EidasErrorKey.INVALID_SESSION.errorMessage()));
            }

            final IPersonalAttributeList pal = (PersonalAttributeList) sigCreatorReturn.getSession()
                    .get(EidasParameterKeys.ATTRIBUTE_LIST.toString());
            if (pal != null) {
                final PersonalAttribute pAttr = pal.getByFriendlyName(sigCreatorReturn.getAttribute());
                if (null != pAttr && sigCreatorReturn.getSession()
                        .containsKey(EidasParameterKeys.SIGNATURE_RESPONSE.toString())) {
                    if (sigCreatorReturn.getSession()
                            .get(EidasParameterKeys.SIGNATURE_RESPONSE.toString()) instanceof ArrayList<?>) {
                        LOG.debug("[execute] Session's signatureResponse is OK");
                        final List<String> values = (List<String>) sigCreatorReturn.getSession()
                                .get(EidasParameterKeys.SIGNATURE_RESPONSE.toString());

                        pAttr.setValue(values);
                        pal.add(pAttr);
                        IEidasAuthenticationRequest authData =
                                (IEidasAuthenticationRequest) sigCreatorReturn.getSession()
                                        .get(EidasParameterKeys.AUTH_REQUEST.toString());

                        IPersonalAttributeList sessionPal =
                                PersonalAttributeList.copyOf(authData.getRequestedAttributes());
                        sessionPal.add(pAttr);
                        EidasAuthenticationRequest.Builder eIDASAuthnRequestBuilder =
                                EidasAuthenticationRequest.builder(authData);
                        ProtocolProcessorI protocolProcessor =
                                ProtocolEngineFactory.getDefaultProtocolEngine("Specific").getProtocolProcessor();
                        eIDASAuthnRequestBuilder.requestedAttributes(
                                PersonalAttributeList.retainAttrsExistingInRegistry(sessionPal,
                                                                                    protocolProcessor.getMinimumDataSetAttributes(),
                                                                                    protocolProcessor.getAdditionalAttributes()));

                        sigCreatorReturn.getSession().put(EidasParameterKeys.AUTH_REQUEST.toString(), authData);
                        attrList = (PersonalAttributeList) pal;
                    } else {
                        LOG.info("ERROR : [execute] Session's signatureResponse isn't a ArrayList: "
                                         + sigCreatorReturn.getSession()
                                .get(EidasParameterKeys.SIGNATURE_RESPONSE.toString()));
                    }
                }
            } else {
                LOG.info("ERROR : [execute] Session's Personal Attribute List is null");
            }

            sigCreatorReturn.getSession().remove(EidasParameterKeys.ATTRIBUTE_LIST.toString());

            request.setAttribute(EidasParameterKeys.ATTRIBUTE_LIST.toString(), attrList);
            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(
                    response.encodeURL(SpecificViewNames.IDP_RESPONSE.toString()));
            dispatcher.forward(request, response);

        } catch (AbstractEIDASException e) {
            LOG.info("ERROR : ", e.getErrorMessage());
            LOG.debug("ERROR : ", e);
            throw e;
        }
    }
}
