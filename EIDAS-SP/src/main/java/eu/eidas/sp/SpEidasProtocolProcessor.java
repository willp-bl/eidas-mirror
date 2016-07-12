/*
 * Copyright (c) 2016 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
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

package eu.eidas.sp;

import com.google.common.collect.ImmutableSet;
import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.EidasErrors;
import eu.eidas.auth.commons.attribute.*;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.eidas.IEidasAuthenticationRequest;
import eu.eidas.auth.commons.protocol.eidas.LevelOfAssuranceComparison;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequest;
import eu.eidas.auth.engine.AbstractProtocolEngine;
import eu.eidas.auth.engine.core.ProtocolProcessorI;
import eu.eidas.auth.engine.core.SamlEngineCoreProperties;
import eu.eidas.auth.engine.core.eidas.EidasProtocolProcessor;
import eu.eidas.auth.engine.core.eidas.RequestedAttribute;
import eu.eidas.auth.engine.core.eidas.RequestedAttributes;
import eu.eidas.auth.engine.metadata.MetadataFetcherI;
import eu.eidas.auth.engine.metadata.MetadataSignerI;
import eu.eidas.auth.engine.xml.opensaml.BuilderFactoryUtil;
import eu.eidas.auth.engine.xml.opensaml.SAMLEngineUtils;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import org.apache.commons.lang.StringUtils;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by vargata on 23/06/2016.
 */
public class SpEidasProtocolProcessor extends EidasProtocolProcessor implements ProtocolProcessorI {

    /**
     * The LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SpEidasProtocolProcessor.class);

    public SpEidasProtocolProcessor(@Nullable MetadataFetcherI metadataFetcher, @Nullable MetadataSignerI metadataSigner) {
        super(metadataFetcher, metadataSigner);
    }

    public SpEidasProtocolProcessor(@Nonnull AttributeRegistry additionalAttributeRegistry, @Nullable MetadataFetcherI metadataFetcher, @Nullable MetadataSignerI metadataSigner) {
        super(additionalAttributeRegistry, metadataFetcher, metadataSigner);
    }

    public SpEidasProtocolProcessor(@Nonnull String additionalAttributesFileName, @Nullable MetadataFetcherI metadataFetcher, @Nullable MetadataSignerI metadataSigner) {
        super(additionalAttributesFileName, metadataFetcher, metadataSigner);
    }

    public SpEidasProtocolProcessor(@Nonnull String eidasAttributesFileName, @Nonnull String additionalAttributesFileName, @Nullable MetadataFetcherI metadataFetcher, @Nullable MetadataSignerI metadataSigner) {
        super(eidasAttributesFileName, additionalAttributesFileName, metadataFetcher, metadataSigner);
    }

    public SpEidasProtocolProcessor(@Nonnull AttributeRegistry eidasAttributeRegistry, @Nonnull AttributeRegistry additionalAttributeRegistry, @Nullable MetadataFetcherI metadataFetcher, @Nullable MetadataSignerI metadataSigner) {
        super(eidasAttributeRegistry, additionalAttributeRegistry, metadataFetcher, metadataSigner);
    }

    @Override
    @Nonnull
    public IAuthenticationRequest unmarshallRequest(@Nonnull String citizenCountryCode,
                                                    @Nonnull AuthnRequest samlRequest,
                                                    @Nullable String originCountryCode)
            throws EIDASSAMLEngineException {

        LOG.debug("Process the extensions for EIDAS 1.0 messageFormat - SP DEV mode");
        Extensions extensions = samlRequest.getExtensions();
        RequestedAttributes requestedAttr =
                (RequestedAttributes) extensions.getUnknownXMLObjects(RequestedAttributes.DEF_ELEMENT_NAME).get(0);

        List<RequestedAttribute> reqAttrs = requestedAttr.getAttributes();

        ImmutableAttributeMap.Builder attributeMapBuilder = new ImmutableAttributeMap.Builder();
        for (RequestedAttribute attribute : reqAttrs) {
            AttributeDefinition<?> attributeDefinition = getAttributeDefinitionNullable(attribute.getName());

            String friendlyName = attribute.getFriendlyName();
            // Check if friendlyName matches when provided
            if (StringUtils.isNotEmpty(friendlyName) &&
                    attributeDefinition != null &&
                    !friendlyName.equals(attributeDefinition.getFriendlyName())) {
                LOG.error("BUSINESS EXCEPTION : Illegal Attribute friendlyName for " + attributeDefinition.getNameUri().toString() +
                        " expected " +  attributeDefinition.getFriendlyName() + " got " + friendlyName);
                throw new EIDASSAMLEngineException(EidasErrorKey.INTERNAL_ERROR.errorCode(),
                        EidasErrorKey.INTERNAL_ERROR.errorCode(), "Illegal Attribute friendlyName for " + attributeDefinition.getNameUri().toString() +
                        " expected " +  attributeDefinition.getFriendlyName() + " got " + friendlyName);
            }
            List<String> stringValues = new ArrayList<>();
            for (XMLObject xmlObject : attribute.getOrderedChildren()) {
                // Process simple attributes.
                // An AuthenticationRequest must contain simple values only.
                String value;
                if (xmlObject instanceof XSStringImpl) {
                    XSStringImpl xmlString = (XSStringImpl) xmlObject;
                    value = xmlString.getValue();
                } else {
                    XSAnyImpl xmlString = (XSAnyImpl) xmlObject;
                    value = xmlString.getTextContent();
                }
                stringValues.add(value);
            }
            AttributeValueMarshaller<?> attributeValueMarshaller = attributeDefinition.getAttributeValueMarshaller();
            ImmutableSet.Builder<eu.eidas.auth.commons.attribute.AttributeValue<?>> setBuilder = ImmutableSet.builder();
            for (final String value : stringValues) {
                eu.eidas.auth.commons.attribute.AttributeValue<?> attributeValue;
                try {
                    attributeValue = attributeValueMarshaller.unmarshal(value, false);
                } catch (AttributeValueMarshallingException e) {
                    LOG.error("Illegal attribute value: " + e, e);
                    throw new EIDASSAMLEngineException(
                            EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()),
                            EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()), e);
                }
            }
            attributeMapBuilder.put((AttributeDefinition) attributeDefinition, (ImmutableSet) setBuilder.build());
        }

        EidasAuthenticationRequest.Builder builder = new EidasAuthenticationRequest.Builder();
        builder.originCountryCode(originCountryCode);
        builder.assertionConsumerServiceURL(samlRequest.getAssertionConsumerServiceURL());
        builder.binding(SAMLEngineUtils.getBindingMethod(samlRequest.getProtocolBinding()));
        builder.citizenCountryCode(citizenCountryCode);
        builder.destination(samlRequest.getDestination());
        builder.id(samlRequest.getID());
        builder.issuer(samlRequest.getIssuer().getValue());
        builder.levelOfAssurance(extractLevelOfAssurance(samlRequest));
        builder.nameIdFormat(null == samlRequest.getNameIDPolicy() ? null : samlRequest.getNameIDPolicy().getFormat());
        builder.providerName(samlRequest.getProviderName());
        builder.requestedAttributes(attributeMapBuilder.build());
        // eIDAS only:
        builder.levelOfAssuranceComparison(LevelOfAssuranceComparison.MINIMUM.stringValue());
        builder.spType(getNullableSPTypeFromExtension(extensions));

        try {
            return builder.build();
        } catch (IllegalArgumentException e) {
            throw new EIDASSAMLEngineException(
                    EidasErrors.get(EidasErrorKey.ILLEGAL_ARGUMENTS_IN_BUILDER.errorCode()) + " - " + e.getMessage(),
                    e);
        }
    }

    @Nonnull
    @Override
    public AuthnRequest marshallRequest(@Nonnull IAuthenticationRequest request,
                                        @Nonnull String serviceIssuer,
                                        @Nonnull SamlEngineCoreProperties coreProperties)
            throws EIDASSAMLEngineException {

        String id = SAMLEngineUtils.generateNCName();

        AuthnRequest samlRequest =
                BuilderFactoryUtil.generateAuthnRequest(id, SAMLVersion.VERSION_20, SAMLEngineUtils.getCurrentTime());

        // Set name spaces.
        registerRequestNamespace(samlRequest);

        // Add parameter Mandatory
        samlRequest.setForceAuthn(Boolean.TRUE);

        // Add parameter Mandatory
        samlRequest.setIsPassive(Boolean.FALSE);

        samlRequest.setAssertionConsumerServiceURL(request.getAssertionConsumerServiceURL());

        samlRequest.setProviderName(request.getProviderName());

        // Add protocol binding
        samlRequest.setProtocolBinding(getProtocolBinding(request, coreProperties));

        // Add parameter optional
        // Destination is mandatory
        // The application must to know the destination
        if (StringUtils.isNotBlank(request.getDestination())) {
            samlRequest.setDestination(request.getDestination());
        }

        // Consent is optional. Set from SAMLEngine.xml - consent.
        samlRequest.setConsent(coreProperties.getConsentAuthnRequest());

        Issuer issuer = BuilderFactoryUtil.generateIssuer();

        if (request.getIssuer() != null) {
            issuer.setValue(SAMLEngineUtils.getValidIssuerValue(request.getIssuer()));
        } else {
            issuer.setValue(coreProperties.getRequester());
        }

        // Optional
        String formatEntity = coreProperties.getFormatEntity();
        if (StringUtils.isNotBlank(formatEntity)) {
            issuer.setFormat(formatEntity);
        }

        samlRequest.setIssuer(issuer);
        addRequestedAuthnContext(request, samlRequest);

        // Generate format extensions.
        Extensions formatExtensions = generateExtensions(request);
        // add the extensions to the SAMLAuthnRequest
        samlRequest.setExtensions(formatExtensions);
        addNameIDPolicy(samlRequest, request.getNameIdFormat());

        return samlRequest;
    }


}
