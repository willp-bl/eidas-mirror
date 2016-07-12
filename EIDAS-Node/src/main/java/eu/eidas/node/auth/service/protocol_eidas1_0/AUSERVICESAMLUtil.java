/*
 * Copyright (c) 2015 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.eidas.node.auth.service.protocol_eidas1_0;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.eidas.SPType;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.node.utils.EidasNodeValidationUtil;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Utility class dedicated to EIDAS SAML operations
 */
public class AUSERVICESAMLUtil {
    private AUSERVICESAMLUtil(){
        // Private default constructor for utility class.
    }
    /**
     * Logger object.
     */
    protected static final Logger LOGGER = LoggerFactory.getLogger(AUSERVICESAMLUtil.class.getName());

    private static boolean checkLoA(final EIDASAuthnRequest authnRequest, final String stringMaxLoA) {
         return EidasNodeValidationUtil.isRequestLoAValid(authnRequest, stringMaxLoA);
    }

    protected static String getSPAssertionURL(final SPSSODescriptor spDesc) {
        if (spDesc == null || spDesc.getAssertionConsumerServices().isEmpty())
            return null;
        String assertionUrl = spDesc.getAssertionConsumerServices().get(0).getLocation();
        for (AssertionConsumerService acs : spDesc.getAssertionConsumerServices()) {
            if (acs.isDefault()) {
                assertionUrl = acs.getLocation();
            }
        }
        return assertionUrl;
    }
    /**
     * Retrieve SPType published in the metadata of the requesting party.
     *
     * @param entityDescriptor the entitity descriptor to use
     * @return the value of spType (either 'public' or 'private')
     */
    protected static String getSPTypeFromMetadata(final EntityDescriptor entityDescriptor) {
        if (entityDescriptor == null || entityDescriptor.getExtensions() == null) {
            return null;
        }
        List<XMLObject> spTypes = entityDescriptor.getExtensions().getUnknownXMLObjects(SPType.DEF_ELEMENT_NAME);
        final SPType type = (SPType) (spTypes.isEmpty() ? null : spTypes.get(0));
        return type == null ? null : type.getSPType();
    }

    /**
     * check: the provided assertionurl(if any) against that retrieved from the metadata
     * the binding versus actual http method
     * @return true if an SamlAuthentication error needs to be sent
     * CAVEAT: eidas configuration needs active metadata usage
     *
     */
    public static boolean eidasValidationSentSamlAuthticationError(final EIDASSAMLEngine engine, final EIDASAuthnRequest authnRequest,
                  final IEIDASSession session, final MetadataProcessorI metadataProcessor,
                  final boolean validateBinding, final String stringMaxLoA) {
        try {
            if (!checkLoA(authnRequest, stringMaxLoA) || metadataProcessor== null){
                return true;
            }

            metadataProcessor.checkValidMetadataSignature(authnRequest.getIssuer(), engine);
            SPSSODescriptor spDesc = metadataProcessor.getSPSSODescriptor(authnRequest.getIssuer());

            String metadataAssertionUrl = getSPAssertionURL(spDesc);
            if ((StringUtils.isEmpty(metadataAssertionUrl)
                    || (authnRequest.getAssertionConsumerServiceURL() != null && !authnRequest.getAssertionConsumerServiceURL().equals(metadataAssertionUrl)))) {
                throw new InternalErrorEIDASException(
                        EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                        EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()));

            }
            authnRequest.setAssertionConsumerServiceURL(metadataAssertionUrl);

            if (validateBinding) {
                boolean isBindingValid = false;
                String currentMethod = (String) session.get(EIDASParameters.HTTP_METHOD.toString());
                for (AssertionConsumerService asc : spDesc.getAssertionConsumerServices()) {
                    if (currentMethod != null && currentMethod.equalsIgnoreCase(SAMLEngineUtils.getBindingMethod(asc.getBinding()))) {
                        isBindingValid = true;
                        break;
                    }
                }
                if (!isBindingValid) {
                    LOGGER.info("The issuer {} does not support {}", authnRequest.getIssuer(), currentMethod);
                    throw new InternalErrorEIDASException(EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()), EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()),
                            new InternalErrorEIDASException(EIDASUtil.getConfig(EIDASErrors.INVALID_PROTOCOL_BINDING.errorCode()), EIDASUtil.getConfig(EIDASErrors.INVALID_PROTOCOL_BINDING.errorMessage())));
                }
            }

            String requestSpType = authnRequest.getSPType();
            String metadataSpType = getSPTypeFromMetadata(metadataProcessor.getEntityDescriptor(authnRequest.getIssuer()));
            //exactly one of requestSpType, metadataSpType should be non empty
            if (StringUtils.isEmpty(requestSpType)) {
                if (StringUtils.isEmpty(metadataSpType)) {
                    throw new EIDASServiceException("", EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_MISSING_SPTYPE.errorCode()),
                            EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_MISSING_SPTYPE.errorMessage()));
                }
            } else if (!StringUtils.isEmpty(metadataSpType)) {
                throw new EIDASServiceException("", EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INCONSISTENT_SPTYPE.errorCode()),
                        EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INCONSISTENT_SPTYPE.errorMessage()));
            }
        } catch (SAMLEngineException e) {
            throw new InternalErrorEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorMessage()), e);
        }
        return false;
    }
}
