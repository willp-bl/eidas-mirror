/* 
#   Copyright (c) 2017 European Commission  
#   Licensed under the EUPL, Version 1.2 or – as soon they will be 
#   approved by the European Commission - subsequent versions of the 
#    EUPL (the "Licence"); 
#    You may not use this work except in compliance with the Licence. 
#    You may obtain a copy of the Licence at: 
#    * https://joinup.ec.europa.eu/page/eupl-text-11-12  
#    *
#    Unless required by applicable law or agreed to in writing, software 
#    distributed under the Licence is distributed on an "AS IS" basis, 
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#    See the Licence for the specific language governing permissions and limitations under the Licence.
 */
package eu.eidas.auth.engine;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.support.SignatureException;

import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.attribute.impl.StringAttributeValue;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.IAuthenticationResponse;
import eu.eidas.auth.commons.protocol.IRequestMessage;
import eu.eidas.auth.commons.protocol.IResponseMessage;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequest;
import eu.eidas.auth.commons.protocol.eidas.spec.EidasSpec;
import eu.eidas.auth.commons.protocol.impl.AuthenticationResponse;
import eu.eidas.auth.commons.protocol.impl.BinaryRequestMessage;
import eu.eidas.auth.commons.xml.opensaml.OpenSamlHelper;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * ProtocolEngineTest
 *
 * @since 1.1
 */
public final class ProtocolEngineTest {


    @Test
    public void testUnmarshallRequestAndValidateWithManipulateIssuerWithoutResigning() throws Exception {

        ProtocolEngineI protocolEngine = DefaultProtocolEngineFactory.getInstance().getProtocolEngine("METADATATEST");

        EidasAuthenticationRequest request = EidasAuthenticationRequest.builder()
                .id("_1")
                .issuer("https://source.europa.eu/metadata")
                .destination("https://destination.europa.eu")
                .citizenCountryCode("BE")
                .originCountryCode("BE")
                .providerName("Prov")
                .assertionConsumerServiceURL("https://source.europa.eu/metadata")
                .requestedAttributes(ImmutableAttributeMap.of(EidasSpec.Definitions.PERSON_IDENTIFIER,
                                                              new StringAttributeValue[] {}))
                .build();

        IRequestMessage requestMessage =
                protocolEngine.generateRequestMessage(request, "https://destination.europa.eu/metadata");
        

        //1. Successful unmarshalling (including validation/signature)
        String citizenCountryCode="BE";
        try{
        	protocolEngine.unmarshallRequestAndValidate(requestMessage.getMessageBytes(), citizenCountryCode);
        }catch(EIDASSAMLEngineException e){
        	fail("Unexpected failure when unmarshalling and validating signature");
        }
        
        //2. 'manipulate' issuer and unmarshall 
        try{
        	final String BOGUS_ISSUER="https://source.america.am/metadata";
        	EidasAuthenticationRequest eAuthnReq = (EidasAuthenticationRequest)requestMessage.getRequest();

        	//2.1. 'manipulating' issuer only without the binary payload will be unsuccessful as assertion proves  
        	EidasAuthenticationRequest manipulated = eAuthnReq.builder(eAuthnReq).issuer(BOGUS_ISSUER).build();
        	BinaryRequestMessage manipulatedMessage = new BinaryRequestMessage(manipulated, requestMessage.getMessageBytes());
        	IAuthenticationRequest manipulatedAuthReq = protocolEngine.unmarshallRequestAndValidate(manipulatedMessage.getMessageBytes(), citizenCountryCode);
        	assertFalse(manipulatedAuthReq.getIssuer().equals(BOGUS_ISSUER));

        	//2.2. 'manipulating' issuer including its value in the binary payload will result in a  EIDASSAMLEngineException thrown
        	String messageXmlPayload=new String(manipulatedMessage.getMessageBytes());
        	String messageXmlManipulatedPayload = messageXmlPayload.replaceAll("https://source.europa.eu/metadata" + "</saml2:Issuer>", BOGUS_ISSUER + "</saml2:Issuer>");
        	manipulatedMessage=new BinaryRequestMessage(manipulated, messageXmlManipulatedPayload.getBytes());
        	
        	//this call will throw an EIDASSAMLEngineException due to signature validation
        	manipulatedAuthReq = protocolEngine.unmarshallRequestAndValidate(manipulatedMessage.getMessageBytes(), citizenCountryCode);

        	fail("unmarshallRequestAndValidate of AuthnRequest with manipulated issuer should have failed");
        	
        }catch(EIDASSAMLEngineException e){
        	
        	assertTrue(e.getCause() instanceof SignatureException);

        	final String EXPECTED_SIGNATURE_MESSAGE = "Signature cryptographic validation not successful".toUpperCase();
        	assertTrue(e.getCause().getMessage().toUpperCase().indexOf(EXPECTED_SIGNATURE_MESSAGE) >= 0 );
        	
        }catch(Exception e){
        	e.printStackTrace();
        }
        

    }

    @Test
    public void unmarshallResponseAndValidate() throws Exception {

        ProtocolEngineI protocolEngine = DefaultProtocolEngineFactory.getInstance().getProtocolEngine("METADATATEST");

        EidasAuthenticationRequest request = EidasAuthenticationRequest.builder()
                .id("_1")
                .issuer("https://source.europa.eu/metadata")
                .destination("https://destination.europa.eu")
                .citizenCountryCode("BE")
                .originCountryCode("BE")
                .providerName("Prov")
                .assertionConsumerServiceURL("https://source.europa.eu/metadata")
                .requestedAttributes(ImmutableAttributeMap.of(EidasSpec.Definitions.PERSON_IDENTIFIER,
                                                              new StringAttributeValue[] {}))
                .build();

        IRequestMessage requestMessage =
                protocolEngine.generateRequestMessage(request, "https://destination.europa.eu/metadata");

        AuthenticationResponse response = AuthenticationResponse.builder()
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .id("_2")
                .inResponseTo(request.getId())
                .issuer("https://destination.europa.eu/metadata")
                .subject("UK/UK/Bankys")
                .subjectNameIdFormat("urn:oasis:names:tc:saml2:2.0:nameid-format:persistent")
                .attributes(ImmutableAttributeMap.of(EidasSpec.Definitions.PERSON_IDENTIFIER,
                        new StringAttributeValue("LU/BE/1", false)))
                .build();

        IResponseMessage responseMessage = protocolEngine.generateResponseMessage(request, response, true, "127.0.0.1");

        System.out.println("responseMessage = " + EidasStringUtil.toString(responseMessage.getMessageBytes()));
        // hack to look inside what was really generated:
        Response samlResponse = (Response) OpenSamlHelper.unmarshall(responseMessage.getMessageBytes());
        assertFalse(samlResponse.getEncryptedAssertions().isEmpty());

        Correlated correlated = protocolEngine.unmarshallResponse(responseMessage.getMessageBytes());

        IAuthenticationResponse authenticationResponse =
                protocolEngine.validateUnmarshalledResponse(correlated, "127.0.0.1", 0L, 0L, null);

        assertFalse(authenticationResponse.getStatus().isFailure());
    }
}
