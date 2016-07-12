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
package eu.eidas.node.auth.service;

import java.nio.charset.Charset;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.CitizenConsent;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.node.utils.EidasNodeValidationUtil;

/**
 * The AUSERVICE class deals with the requests coming from the Connector. This class
 * communicates with the IdP and APs in order to authenticate the citizen,
 * validate the attributes provided by him/her, and to request the values of the
 * citizen's attributes.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.82 $, $Date: 2011-07-07 20:53:51 $
 * @see ISERVICEService
 */
public final class AUSERVICE implements ISERVICEService {

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUSERVICE.class.getName());

    /**
     * Service for citizen related operations.
     */
    private ISERVICECitizenService citizenService;

    /**
     * Service for SAML related operations.
     */
    private ISERVICESAMLService samlService;

    /**
     * Service for translation related operations.
     */
    private ISERVICETranslatorService transService;

    /**
     * {@inheritDoc}
     */
    public EIDASAuthnRequest processAuthenticationRequest(
            final Map<String, String> parameters, final IEIDASSession session) {

        // fetch the samlToken from the request
        final byte[] samlToken =
                samlService.getSAMLToken(parameters.get(EIDASParameters.SAML_REQUEST
                        .toString()));

        session.put(EIDASParameters.HTTP_METHOD.toString(), parameters.get(EIDASParameters.HTTP_METHOD.toString()));
        // validate samlToken and populate AuthenticationData
        final EIDASAuthnRequest authData =
                samlService.processAuthenticationRequest(samlToken, session,
                        parameters.get(EIDASParameters.REMOTE_ADDR.toString()));

        session.put(EIDASParameters.AUTH_REQUEST.toString(), authData);

        LOG.trace("Validating destination");
        EIDASUtil.validateParameter(AUSERVICE.class.getCanonicalName(),
                EIDASErrors.SERVICE_REDIRECT_URL.toString(), authData.getDestination());

        // normalize attributes from format
        final IPersonalAttributeList pal =
                transService.normaliseAttributeNamesFromFormat(authData
                        .getPersonalAttributeList());
        citizenService.updateAttributeList(session, pal);
        return authData;
    }

    /**
     * {@inheritDoc}
     */
    public IPersonalAttributeList processCitizenConsent(
            final Map<String, String> parameters, final IEIDASSession session,
            final boolean askConsentType) {

        final EIDASAuthnRequest authData =
                (EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST.toString());

        if (askConsentType) {
            // construct citizen consent from the request
            final CitizenConsent consent =
                    citizenService.getCitizenConsent(parameters,
                            authData.getPersonalAttributeList());

            // checks if all mandatory attributes are present in the consent
            citizenService.processCitizenConsent(consent, authData,
                    parameters.get(EIDASParameters.REMOTE_ADDR.toString()), samlService);
            // updates the personalAttributeList, removing the attributes
            // without consent
            final IPersonalAttributeList pal =
                    citizenService.updateAttributeList(consent,
                            authData.getPersonalAttributeList());
            // If the personalAttributeList is empty then we must show a error
            // message.
            if (pal.isEmpty()) {
                LOG.info("BUSINESS EXCEPTION : Attribute List is empty!");
                final byte[] samlTokenFail =
                        samlService.generateErrorAuthenticationResponse(authData,
                                EIDASUtil.getConfig(EIDASErrors.SERVICE_ATTR_NULL.errorCode()), null,
                                EIDASUtil.getConfig(EIDASErrors.SERVICE_ATTR_NULL.errorMessage()),
                                (String) session.get(EIDASParameters.REMOTE_ADDR.toString()), false);
                throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail),
                        EIDASUtil.getConfig(EIDASErrors.SERVICE_ATTR_NULL.errorCode()),
                        EIDASUtil.getConfig(EIDASErrors.SERVICE_ATTR_NULL.errorMessage()));
            }
            // updates the list in session
            citizenService.updateAttributeList(session, pal);
        }

        return transService.deriveAttributesFromFormat(authData
                .getPersonalAttributeList());
    }

    /**
     * {@inheritDoc}
     */
    public void processIdPResponse(final Map<String, String> parameters,
                                   final IEIDASSession session) {

        // Test if an error occurred in the IdP
        sendErrorPage(parameters);

        LOG.trace("Add values from the IdP to attrList");
        final String attrList =
                parameters.get(EIDASParameters.ATTRIBUTE_LIST.toString());
        if (attrList == null) {
            LOG.info("ERROR : Personal Attribute List is null!");
            final EIDASAuthnRequest authData =
                    (EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST.toString());
            final byte[] samlTokenFail =
                    samlService.generateErrorAuthenticationResponse(authData,
                            EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                            null,
                            EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorMessage()),
                            (String) session.get(EIDASParameters.REMOTE_ADDR.toString()), true);

            throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail),
                    EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorMessage()));
        }
        final IPersonalAttributeList pal = new PersonalAttributeList();
        pal.populate(attrList);
        LOG.trace("Updating the personalAttributeList");
        citizenService.updateAttributeListValues(session, pal);
    }

    /**
     * {@inheritDoc}
     */
    public EIDASAuthnRequest processAPResponse(
            final Map<String, String> parameters, final IEIDASSession session) {

        final EIDASAuthnRequest authDataObj = (EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST.toString());

        EIDASAuthnRequest authData = null;
        try {
            authData = (EIDASAuthnRequest) authDataObj.clone();
            if (authData != null){
                LOG.trace("Loading personalAttributeList from AP");

                final String strPal =
                        parameters.get(EIDASParameters.ATTRIBUTE_LIST.toString());
                if (strPal == null) {
                    LOG.info("ERROR : Personal Attribute List is null!");
                    final byte[] samlTokenFail =
                            samlService.generateErrorAuthenticationResponse(authData,
                                    EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                                    null,
                                    EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorMessage()),
                                    (String) session.get(EIDASParameters.REMOTE_ADDR.toString()), true);

                    throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(samlTokenFail),
                            EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                            EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorMessage()));
                }
                IPersonalAttributeList pal = new PersonalAttributeList();
                pal.populate(strPal);

                citizenService.updateAttributeListValues(session, pal);
                // Derive Attributes to current Format
                authData.setPersonalAttributeList(pal);
                pal =
                        transService.deriveAttributesToFormat(samlService, session, authData,
                                parameters.get(EIDASParameters.REMOTE_ADDR.toString()));
                pal = citizenService.updateAttributeList(session, pal);

                // normalizing names to current format
                IPersonalAttributeList attrList = null;
                attrList = transService.normaliseAttributeNamesToFormat((IPersonalAttributeList) pal.clone());
                authData.setPersonalAttributeList(attrList);
                // normalizing values to current format
                attrList =
                        transService.normaliseAttributeValuesToFormat(samlService, authData,
                                parameters.get(EIDASParameters.REMOTE_ADDR.toString()));
                citizenService.updateAttributeList(session, attrList);

                // check if all mandatory attributes have values
                samlService.checkMandatoryAttributes(authData, 
                        parameters.get(EIDASParameters.REMOTE_ADDR.toString()));
                samlService.validateAPResponses(authData, session, parameters.get(EIDASParameters.REMOTE_ADDR.toString()));

                samlService.checkAttributeValues(authData,
                        parameters.get(EIDASParameters.REMOTE_ADDR.toString()));

                final byte[] auth =
                        samlService.generateAuthenticationResponse(authData,
                                (String) session.get(EIDASParameters.REMOTE_ADDR.toString()), true);
                LOG.trace("Setting attribute SAML_TOKEN");

                authData.setPersonalAttributeList(pal);
                authData.setTokenSaml(EIDASUtil.encodeSAMLToken(auth).getBytes(Charset.forName("UTF-8")));
            }
        } catch (CloneNotSupportedException e) {
            LOG.info("Clone not done - [PersonalAttribute] Nothing to do.", e.getMessage());
            LOG.debug("Clone not done - [PersonalAttribute] Nothing to do.", e);
        }
        return authData;
    }

    /**
     * {@inheritDoc}
     */
    public String generateSamlTokenFail(final EIDASAuthnRequest authData,
                                        final EIDASErrors error, final String ipUserAddress) {

        final byte[] eauth =
                samlService.generateErrorAuthenticationResponse(authData,
                        EIDASUtil.getConfig(error.errorCode()),
                        EIDASSubStatusCode.REQUEST_DENIED_URI.toString(),
                        EIDASUtil.getConfig(error.errorMessage()), ipUserAddress, false);

        return EIDASUtil.encodeSAMLToken(eauth);
    }

    /**
     * Generates a exception with an embedded SAML token.
     *
     * @param parameters A map of parameters to generate the error token.
     * @see IEIDASSession
     * @see Map
     */
    private void sendErrorPage(final Map<String, String> parameters) {

        if (parameters.get(EIDASParameters.ERROR_CODE.toString()) != null) {
            final String exErrorCode =
                    EIDASUtil.getConfig(EIDASErrors.AUTHENTICATION_FAILED_ERROR.errorCode());
            final String exErrorMessage = EIDASUtil.getConfig(EIDASErrors.AUTHENTICATION_FAILED_ERROR.errorMessage());
            throw new EIDASServiceException(null, exErrorCode, exErrorMessage);
        }
    }

    /**
     * Setter for citizenService.
     *
     * @param nCitizenService The new citizenService value.
     * @see ISERVICECitizenService
     */
    public void setCitizenService(final ISERVICECitizenService nCitizenService) {
        this.citizenService = nCitizenService;
    }

    /**
     * Getter for citizenService.
     *
     * @return The citizenService value.
     * @see ISERVICECitizenService
     */
    public ISERVICECitizenService getCitizenService() {
        return citizenService;
    }

    /**
     * Setter for samlService.
     *
     * @param nSamlService The new samlService value.
     * @see ISERVICESAMLService
     */
    public void setSamlService(final ISERVICESAMLService nSamlService) {
        this.samlService = nSamlService;
    }

    /**
     * Getter for samlService.
     *
     * @return The samlService value.
     * @see ISERVICESAMLService
     */
    public ISERVICESAMLService getSamlService() {
        return samlService;
    }

    /**
     * Setter for transService.
     *
     * @param theTransService The new transService value.
     * @see ISERVICETranslatorService
     */
    public void setTransService(final ISERVICETranslatorService theTransService) {
        this.transService = theTransService;
    }

    /**
     * Getter for transService.
     *
     * @return The transService value.
     * @see ISERVICETranslatorService
     */
    public ISERVICETranslatorService getTransService() {
        return transService;
    }
}
