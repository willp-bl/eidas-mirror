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
package eu.stork.peps.auth.cpeps;

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.CPEPSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.util.Map;

/**
 * The AUCPEPS class deals with the requests coming from the S-PEPS. This class
 * communicates with the IdP and APs in order to authenticate the citizen,
 * validate the attributes provided by him/her, and to request the values of the
 * citizen's attributes.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.82 $, $Date: 2011-07-07 20:53:51 $
 * @see ICPEPSService
 */
public final class AUCPEPS implements ICPEPSService {

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUCPEPS.class.getName());

    /**
     * Service for citizen related operations.
     */
    private ICPEPSCitizenService citizenService;

    /**
     * Service for SAML related operations.
     */
    private ICPEPSSAMLService samlService;

    /**
     * Service for translation related operations.
     */
    private ICPEPSTranslatorService transService;

    /**
     * {@inheritDoc}
     */
    public STORKAuthnRequest processAuthenticationRequest(
            final Map<String, String> parameters, final IStorkSession session) {

        // fetch the samlToken from the request
        final byte[] samlToken =
                samlService.getSAMLToken(parameters.get(PEPSParameters.SAML_REQUEST
                        .toString()));

        session.put(PEPSParameters.HTTP_METHOD.toString(), parameters.get(PEPSParameters.HTTP_METHOD.toString()));
        // validate samlToken and populate AuthenticationData
        final STORKAuthnRequest authData =
                samlService.processAuthenticationRequest(samlToken, session,
                        parameters.get(PEPSParameters.REMOTE_ADDR.toString()));

        session.put(PEPSParameters.AUTH_REQUEST.toString(), authData);

        LOG.trace("Validating destination");
        PEPSUtil.validateParameter(AUCPEPS.class.getCanonicalName(),
                PEPSErrors.CPEPS_REDIRECT_URL.toString(), authData.getDestination());

        // normalize attributes from STORK format
        final IPersonalAttributeList pal =
                transService.normaliseAttributeNamesFromStork(authData
                        .getPersonalAttributeList());
        citizenService.updateAttributeList(session, pal);
        return authData;
    }

    /**
     * {@inheritDoc}
     */
    public IPersonalAttributeList processCitizenConsent(
            final Map<String, String> parameters, final IStorkSession session,
            final boolean askConsentType) {

        final STORKAuthnRequest authData =
                (STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST.toString());

        if (askConsentType) {
            // construct citizen consent from the request
            final CitizenConsent consent =
                    citizenService.getCitizenConsent(parameters,
                            authData.getPersonalAttributeList());

            // checks if all mandatory attributes are present in the consent
            citizenService.processCitizenConsent(consent, authData,
                    parameters.get(PEPSParameters.REMOTE_ADDR.toString()), samlService);
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
                                PEPSUtil.getConfig(PEPSErrors.CPEPS_ATTR_NULL.errorCode()), null,
                                PEPSUtil.getConfig(PEPSErrors.CPEPS_ATTR_NULL.errorMessage()),
                                (String) session.get(PEPSParameters.REMOTE_ADDR.toString()), false);
                throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail),
                        PEPSUtil.getConfig(PEPSErrors.CPEPS_ATTR_NULL.errorCode()),
                        PEPSUtil.getConfig(PEPSErrors.CPEPS_ATTR_NULL.errorMessage()));
            }
            // updates the list in session
            citizenService.updateAttributeList(session, pal);
        }

        return transService.deriveAttributesFromStork(authData
                .getPersonalAttributeList());
    }

    /**
     * {@inheritDoc}
     */
    public void processIdPResponse(final Map<String, String> parameters,
                                   final IStorkSession session) {

        // Test if an error occurred in the IdP
        sendErrorPage(parameters);

        LOG.trace("Add values from the IdP to attrList");
        final String attrList =
                parameters.get(PEPSParameters.ATTRIBUTE_LIST.toString());
        if (attrList == null) {
            LOG.info("ERROR : Personal Attribute List is null!");
            final STORKAuthnRequest authData =
                    (STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST.toString());
            final byte[] samlTokenFail =
                    samlService.generateErrorAuthenticationResponse(authData,
                            PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                            null,
                            PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorMessage()),
                            (String) session.get(PEPSParameters.REMOTE_ADDR.toString()), true);

            throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail),
                    PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorMessage()));
        }
        final IPersonalAttributeList pal = new PersonalAttributeList();
        pal.populate(attrList);
        LOG.trace("Updating the personalAttributeList");
        citizenService.updateAttributeListValues(session, pal);
    }

    /**
     * {@inheritDoc}
     */
    public STORKAuthnRequest processAPResponse(
            final Map<String, String> parameters, final IStorkSession session) {

        final STORKAuthnRequest authDataObj = (STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST.toString());

        STORKAuthnRequest authData = null;
        try {
            authData = (STORKAuthnRequest) authDataObj.clone();
            if (authData != null){
                LOG.trace("Loading personalAttributeList from AP");

                final String strPal =
                        parameters.get(PEPSParameters.ATTRIBUTE_LIST.toString());
                if (strPal == null) {
                    LOG.info("ERROR : Personal Attribute List is null!");
                    final byte[] samlTokenFail =
                            samlService.generateErrorAuthenticationResponse(authData,
                                    PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                                    null,
                                    PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorMessage()),
                                    (String) session.get(PEPSParameters.REMOTE_ADDR.toString()), true);

                    throw new CPEPSException(PEPSUtil.encodeSAMLToken(samlTokenFail),
                            PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorCode()),
                            PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorMessage()));
                }
                IPersonalAttributeList pal = new PersonalAttributeList();
                pal.populate(strPal);

                citizenService.updateAttributeListValues(session, pal);
                // Derive Attributes to Stork Format
                authData.setPersonalAttributeList(pal);
                pal =
                        transService.deriveAttributesToStork(samlService, session, authData,
                                parameters.get(PEPSParameters.REMOTE_ADDR.toString()));
                pal = citizenService.updateAttributeList(session, pal);

                // normalizing names to STORK format
                IPersonalAttributeList attrList = null;
                attrList = transService.normaliseAttributeNamesToStork((IPersonalAttributeList) pal.clone());
                authData.setPersonalAttributeList(attrList);
                // normalizing values to STORK format
                attrList =
                        transService.normaliseAttributeValuesToStork(samlService, authData,
                                parameters.get(PEPSParameters.REMOTE_ADDR.toString()));
                citizenService.updateAttributeList(session, attrList);

                // check if all mandatory attributes have values
                samlService.checkMandatoryAttributes(authData,
                        parameters.get(PEPSParameters.REMOTE_ADDR.toString()));

                samlService.checkAttributeValues(authData,
                        parameters.get(PEPSParameters.REMOTE_ADDR.toString()));

                final byte[] auth =
                        samlService.generateAuthenticationResponse(authData,
                                (String) session.get(PEPSParameters.REMOTE_ADDR.toString()), true);
                LOG.trace("Setting attribute SAML_TOKEN");

                authData.setPersonalAttributeList(pal);
                authData.setTokenSaml(PEPSUtil.encodeSAMLToken(auth).getBytes(Charset.forName("UTF-8")));
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
    public String generateSamlTokenFail(final STORKAuthnRequest authData,
                                        final PEPSErrors error, final String ipUserAddress) {

        final byte[] eauth =
                samlService.generateErrorAuthenticationResponse(authData,
                        PEPSUtil.getConfig(error.errorCode()),
                        STORKSubStatusCode.REQUEST_DENIED_URI.toString(),
                        PEPSUtil.getConfig(error.errorMessage()), ipUserAddress, false);

        return PEPSUtil.encodeSAMLToken(eauth);
    }

    /**
     * Generates a exception with an embedded SAML token.
     *
     * @param parameters A map of parameters to generate the error token.
     * @see IStorkSession
     * @see Map
     */
    private void sendErrorPage(final Map<String, String> parameters) {

        if (parameters.get(PEPSParameters.ERROR_CODE.toString()) != null) {
            final String exErrorCode =
                    PEPSUtil.getConfig(PEPSErrors.AUTHENTICATION_FAILED_ERROR.errorCode());
            final String exErrorMessage = PEPSUtil.getConfig(PEPSErrors.AUTHENTICATION_FAILED_ERROR.errorMessage());
            throw new CPEPSException(null, exErrorCode, exErrorMessage);
        }
    }

    /**
     * Setter for citizenService.
     *
     * @param nCitizenService The new citizenService value.
     * @see ICPEPSCitizenService
     */
    public void setCitizenService(final ICPEPSCitizenService nCitizenService) {
        this.citizenService = nCitizenService;
    }

    /**
     * Getter for citizenService.
     *
     * @return The citizenService value.
     * @see ICPEPSCitizenService
     */
    public ICPEPSCitizenService getCitizenService() {
        return citizenService;
    }

    /**
     * Setter for samlService.
     *
     * @param nSamlService The new samlService value.
     * @see ICPEPSSAMLService
     */
    public void setSamlService(final ICPEPSSAMLService nSamlService) {
        this.samlService = nSamlService;
    }

    /**
     * Getter for samlService.
     *
     * @return The samlService value.
     * @see ICPEPSSAMLService
     */
    public ICPEPSSAMLService getSamlService() {
        return samlService;
    }

    /**
     * Setter for transService.
     *
     * @param theTransService The new transService value.
     * @see ICPEPSTranslatorService
     */
    public void setTransService(final ICPEPSTranslatorService theTransService) {
        this.transService = theTransService;
    }

    /**
     * Getter for transService.
     *
     * @return The transService value.
     * @see ICPEPSTranslatorService
     */
    public ICPEPSTranslatorService getTransService() {
        return transService;
    }
}
