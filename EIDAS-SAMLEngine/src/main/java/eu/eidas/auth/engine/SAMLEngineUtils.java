/* 
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */

package eu.eidas.auth.engine;

import eu.eidas.auth.commons.DocumentBuilderFactoryUtil;
import eu.eidas.auth.commons.EidasLoaCompareType;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.engine.core.*;
import eu.eidas.auth.engine.core.eidas.EidasConstants;
import eu.eidas.auth.engine.core.stork.*;
import eu.eidas.auth.engine.core.stork.RequestedAttribute;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineRuntimeException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.samlext.saml2mdattr.EntityAttributes;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEvaluator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;

/**
 * The Class SAMLEngineUtils.
 * 
 * @author fjquevedo
 * @author iinigo
 */
public final class SAMLEngineUtils {

    /** The Constant UTF_8. */
    public static final String UTF_8 = "UTF-8";

    /** The Constant SHA_512. */
    public static final String SHA_512 = "SHA-512";


    /** The generator. */
    private static SecureRandomIdentifierGenerator generator;

    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory
	    .getLogger(SAMLEngineUtils.class.getName());

    /**
     * Method that generates a random value according to NCName grammar.
     *
     * NCName ::= NCNameStartChar NCNameChar* NCNameChar ::= NameChar - ':'
     * NCNameStartChar ::= Letter | '_' NameStartChar ::= ":" | [A-Z] | "_" |
     * [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] | [#x370-#x37D] |
     * [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] |
     * [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
     * NameChar ::= NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] |
     * [#x203F-#x2040] Name ::= NameStartChar (NameChar)* Letter ::= BaseChar |
     * Ideographic BaseChar ::= [#x0041-#x005A] | [#x0061-#x007A] |
     * [#x00C0-#x00D6] | [#x00D8-#x00F6] | [#x00F8-#x00FF] | [#x0100-#x0131] |
     * [#x0134-#x013E] | [#x0141-#x0148] | [#x014A-#x017E] | [#x0180-#x01C3] |
     * [#x01CD-#x01F0] | [#x01F4-#x01F5] | [#x01FA-#x0217] | [#x0250-#x02A8] |
     * [#x02BB-#x02C1] | #x0386 | [#x0388-#x038A] | #x038C | [#x038E-#x03A1] |
     * [#x03A3-#x03CE] | [#x03D0-#x03D6] | #x03DA | #x03DC | #x03DE | #x03E0 |
     * [#x03E2-#x03F3] | [#x0401-#x040C] | [#x040E-#x044F] | [#x0451-#x045C] |
     * [#x045E-#x0481] | [#x0490-#x04C4] | [#x04C7-#x04C8] | [#x04CB-#x04CC] |
     * [#x04D0-#x04EB] | [#x04EE-#x04F5] | [#x04F8-#x04F9] | [#x0531-#x0556] |
     * #x0559 | [#x0561-#x0586] | [#x05D0-#x05EA] | [#x05F0-#x05F2] |
     * [#x0621-#x063A] | [#x0641-#x064A] | [#x0671-#x06B7] | [#x06BA-#x06BE] |
     * [#x06C0-#x06CE] | [#x06D0-#x06D3] | #x06D5 | [#x06E5-#x06E6] |
     * [#x0905-#x0939] | #x093D | [#x0958-#x0961] | [#x0985-#x098C] |
     * [#x098F-#x0990] | [#x0993-#x09A8] | [#x09AA-#x09B0] | #x09B2 |
     * [#x09B6-#x09B9] | [#x09DC-#x09DD] | [#x09DF-#x09E1] | [#x09F0-#x09F1] |
     * [#x0A05-#x0A0A] | [#x0A0F-#x0A10] | [#x0A13-#x0A28] | [#x0A2A-#x0A30] |
     * [#x0A32-#x0A33] | [#x0A35-#x0A36] | [#x0A38-#x0A39] | [#x0A59-#x0A5C] |
     * #x0A5E | [#x0A72-#x0A74] | [#x0A85-#x0A8B] | #x0A8D | [#x0A8F-#x0A91] |
     * [#x0A93-#x0AA8] | [#x0AAA-#x0AB0] | [#x0AB2-#x0AB3] | [#x0AB5-#x0AB9] |
     * #x0ABD | #x0AE0 | [#x0B05-#x0B0C] | [#x0B0F-#x0B10] | [#x0B13-#x0B28] |
     * [#x0B2A-#x0B30] | [#x0B32-#x0B33] | [#x0B36-#x0B39] | #x0B3D |
     * [#x0B5C-#x0B5D] | [#x0B5F-#x0B61] | [#x0B85-#x0B8A] | [#x0B8E-#x0B90] |
     * [#x0B92-#x0B95] | [#x0B99-#x0B9A] | #x0B9C | [#x0B9E-#x0B9F] |
     * [#x0BA3-#x0BA4] | [#x0BA8-#x0BAA] | [#x0BAE-#x0BB5] | [#x0BB7-#x0BB9] |
     * [#x0C05-#x0C0C] | [#x0C0E-#x0C10] | [#x0C12-#x0C28] | [#x0C2A-#x0C33] |
     * [#x0C35-#x0C39] | [#x0C60-#x0C61] | [#x0C85-#x0C8C] | [#x0C8E-#x0C90] |
     * [#x0C92-#x0CA8] | [#x0CAA-#x0CB3] | [#x0CB5-#x0CB9] | #x0CDE |
     * [#x0CE0-#x0CE1] | [#x0D05-#x0D0C] | [#x0D0E-#x0D10] | [#x0D12-#x0D28] |
     * [#x0D2A-#x0D39] | [#x0D60-#x0D61] | [#x0E01-#x0E2E] | #x0E30 |
     * [#x0E32-#x0E33] | [#x0E40-#x0E45] | [#x0E81-#x0E82] | #x0E84 |
     * [#x0E87-#x0E88] | #x0E8A | #x0E8D | [#x0E94-#x0E97] | [#x0E99-#x0E9F] |
     * [#x0EA1-#x0EA3] | #x0EA5 | #x0EA7 | [#x0EAA-#x0EAB] | [#x0EAD-#x0EAE] |
     * #x0EB0 | [#x0EB2-#x0EB3] | #x0EBD | [#x0EC0-#x0EC4] | [#x0F40-#x0F47] |
     * [#x0F49-#x0F69] | [#x10A0-#x10C5] | [#x10D0-#x10F6] | #x1100 |
     * [#x1102-#x1103] | [#x1105-#x1107] | #x1109 | [#x110B-#x110C] |
     * [#x110E-#x1112] | #x113C | #x113E | #x1140 | #x114C | #x114E | #x1150 |
     * [#x1154-#x1155] | #x1159 | [#x115F-#x1161] | #x1163 | #x1165 | #x1167 |
     * #x1169 | [#x116D-#x116E] | [#x1172-#x1173] | #x1175 | #x119E | #x11A8 |
     * #x11AB | [#x11AE-#x11AF] | [#x11B7-#x11B8] | #x11BA | [#x11BC-#x11C2] |
     * #x11EB | #x11F0 | #x11F9 | [#x1E00-#x1E9B] | [#x1EA0-#x1EF9] |
     * [#x1F00-#x1F15] | [#x1F18-#x1F1D] | [#x1F20-#x1F45] | [#x1F48-#x1F4D] |
     * [#x1F50-#x1F57] | #x1F59 | #x1F5B | #x1F5D | [#x1F5F-#x1F7D] |
     * [#x1F80-#x1FB4] | [#x1FB6-#x1FBC] | #x1FBE | [#x1FC2-#x1FC4] |
     * [#x1FC6-#x1FCC] | [#x1FD0-#x1FD3] | [#x1FD6-#x1FDB] | [#x1FE0-#x1FEC] |
     * [#x1FF2-#x1FF4] | [#x1FF6-#x1FFC] | #x2126 | [#x212A-#x212B] | #x212E |
     * [#x2180-#x2182] | [#x3041-#x3094] | [#x30A1-#x30FA] | [#x3105-#x312C] |
     * [#xAC00-#xD7A3] Ideographic ::= [#x4E00-#x9FA5] | #x3007 |
     * [#x3021-#x3029]
     *
     * @return Random ID value
     */

    //Initialization of a generator of identifiers for all token SAML.

    static {
	loadRandomIdentifierGenerator();
    }


    /**
     * Load random identifier generator.
     *
     *@throws EIDASSAMLEngineRuntimeException the EIDASSAML engine runtime exception
     */
    private static void loadRandomIdentifierGenerator() {

	try {
	    generator = new SecureRandomIdentifierGenerator();
	} catch (NoSuchAlgorithmException ex) {
	    LOG.error("Error init SecureRandomIdentifierGenerator", ex);
	    throw new EIDASSAMLEngineRuntimeException(ex);
	}

    }

    /**
     * Creates the SAML object.
     *
     * @param qname the QName
     *
     * @return the XML object
     */
    public static XMLObject createSamlObject(final QName qname) {
		XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(qname);
		return builder==null?null:builder.buildObject(qname);
    }

    /**
     * Creates the SAML object.
     *
     * @param qname the quality name
     * @param qname1 the qname1
     *
     * @return the xML object
     */
    public static XMLObject createSamlObject(final QName qname,
	    final QName qname1) {
	return Configuration.getBuilderFactory().getBuilder(qname1)
		.buildObject(qname, qname1);
    }

    /**
     * Encode value with an specific algorithm.
     *
     * @param value the value
     * @param alg the algorithm
     *
     * @return the string
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static String encode(final String value, final String alg)
	    throws EIDASSAMLEngineException {
	LOG.debug("Encode value with  " + alg + " algorithm.");
	byte[] buffer;

	final StringBuilder hash = new StringBuilder("");
	try {
	    buffer = value.getBytes(UTF_8);
	    MessageDigest msgDig;
	    msgDig = MessageDigest.getInstance(alg);


	    msgDig.update(buffer);
	    final byte[] digest = msgDig.digest();

	    final int signedByte = 0xff;
	    for (byte aux : digest) {
		final int byt = aux & signedByte;
		if (Integer.toHexString(byt).length() == 1) {
		    hash.append('0');
		}
		hash.append(Integer.toHexString(byt));
	    }

	} catch (UnsupportedEncodingException e1) {
	    LOG.info("ERROR : UnsupportedEncodingException: " + UTF_8);
		throw new EIDASSAMLEngineException(
				EIDASErrors.INTERNAL_ERROR.errorCode(),
				EIDASErrors.INTERNAL_ERROR.errorMessage(), e1);
	} catch (NoSuchAlgorithmException e) {
	    LOG.info("ERROR : NoSuchAlgorithmException: " + alg);
	    throw new EIDASSAMLEngineException(
				EIDASErrors.INTERNAL_ERROR.errorCode(),
				EIDASErrors.INTERNAL_ERROR.errorMessage(), e);
	}

	return hash.toString();
    }

    /**
     * Generate assertion.
     *
     * @param version the version
     * @param identifier the identifier
     * @param issueInstant the issue instant
     * @param issuer the issuer
     *
     * @return the assertion
     */
    public static Assertion generateAssertion(final SAMLVersion version,
	    final String identifier, final DateTime issueInstant,
	    final Issuer issuer) {
	final AssertionBuilder assertionBuilder = new AssertionBuilder();
	final Assertion assertion = assertionBuilder.buildObject();
	assertion.setVersion(version);
	assertion.setID(identifier);
	assertion.setIssueInstant(issueInstant);

	// <saml:Issuer>
	assertion.setIssuer(issuer);
	return assertion;
    }

    /**
     * Generate authentication statement.
     *
     * @param authnInstant the authentication instant
     * @param authnContext the authentication context
     *
     * @return the authentication statement
     */
    public static AuthnStatement generateAthnStatement(final DateTime authnInstant,
	    final AuthnContext authnContext) {
	// <saml:AuthnStatement>
	final AuthnStatement authnStatement = (AuthnStatement) SAMLEngineUtils
		.createSamlObject(AuthnStatement.DEFAULT_ELEMENT_NAME);

	authnStatement.setAuthnInstant(authnInstant);
	authnStatement.setAuthnContext(authnContext);

	return authnStatement;
    }





    /**
     * Generate attribute from a list of values.
     *
     * @param name the name of the attribute.
     * @param status the status of the parameter: "Available", "NotAvailable" or
     * "Withheld".
     * @param values the value of the attribute.
     * @param isHashing the is hashing with "SHA-512" algorithm.
     * @return the attribute
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static Attribute generateAttrComplex(final EIDASSAMLEngine engine, final String name,
	    final String status, final Map<String, String> values,
	    final boolean isHashing) throws EIDASSAMLEngineException {
	LOG.debug("Generate attribute complex: " + name);
	final Attribute attribute = (Attribute) SAMLEngineUtils
		.createSamlObject(Attribute.DEFAULT_ELEMENT_NAME);

	attribute.setName(name);
	attribute.setNameFormat(Attribute.URI_REFERENCE);

	attribute.getUnknownAttributes().put(
			new QName(engine.getExtensionProcessor().getFormat().getAssertionNS(), "AttributeStatus",
					engine.getExtensionProcessor().getFormat().getAssertionPrefix()), status);

	if (!values.isEmpty()) {
	    LOG.debug("Add attribute values.");

	    // Create an attribute that contains all XSAny elements.
	    final XSAny attrValue = (XSAny) SAMLEngineUtils.createSamlObject(
		    AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);

	    final Iterator<Entry<String, String>> iterator = values.entrySet()
		    .iterator();
	    while (iterator.hasNext()) {
		final Map.Entry<String, String> pairs = iterator.next();

		final String value = pairs.getValue();

		if (StringUtils.isNotBlank(value)) {
		    // Create the attribute statement
		    final XSAny attrValueSimple = (XSAny) SAMLEngineUtils
			    .createSamlObject(new QName(SAMLCore.STORK10_NS.getValue(),
				    pairs.getKey().toString(),
				    SAMLCore.STORK10_PREFIX.getValue()), XSAny.TYPE_NAME);

		    // if it's necessary encode the information.
		    if (isHashing) {
			attrValueSimple
				.setTextContent(encode(value, SHA_512));
		    } else {
		    	attrValueSimple.setTextContent(value);
		    }

		    attrValue.getUnknownXMLObjects().add(attrValueSimple);
		    attribute.getAttributeValues().add(attrValue);
		}
	    }

	}
	return attribute;
    }

    /**
     * Generate extension.
     *
     * @return the extensions
     */
    public static Extensions generateExtension() {
	final ExtensionsBuilder extensionsBuilder = new ExtensionsBuilder();
	return extensionsBuilder.buildObject(
		"urn:oasis:names:tc:SAML:2.0:protocol", "Extensions", "saml2p");
    }




    /**
     * Generate issuer.
     *
     * @return the issuer
     */
    public static Issuer generateIssuer() {
	return (Issuer) SAMLEngineUtils
		.createSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Generate key info.
     *
     * @return the key info
     */
    public static KeyInfo generateKeyInfo() {
	return (KeyInfo) SAMLEngineUtils
		.createSamlObject(KeyInfo.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Generate name id.
     *
     * @return the name id
     */
    public static NameID generateNameID() {
	return (NameID) SAMLEngineUtils
		.createSamlObject(NameID.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Generate name id.
     *
     * @param nameQualifier the name qualifier
     * @param format the format
     * @param spNameQualifier the sP name qualifier
     *
     * @return the name id
     */
    public static NameID generateNameID(final String nameQualifier,
	    final String format, final String spNameQualifier) {
	// <saml:NameID>
	final NameID nameId = (NameID) Configuration.getBuilderFactory()
		.getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(
			NameID.DEFAULT_ELEMENT_NAME);

	// optional
	nameId.setNameQualifier(nameQualifier);

	// optional
	nameId.setFormat(format);

	// optional
	nameId.setSPNameQualifier(spNameQualifier);

	return nameId;
    }

    /**
     * Generate NCName.
     *
     * @return the string
     */
    public static String generateNCName() {
	return generator.generateIdentifier();
    }



    /**
     * Generate requested attribute.
     *
     * @param name the name
     * @param friendlyName the friendly name
     * @param isRequired the is required
     * @param value the value
     *
     * @return the requested attribute
     */
    public static RequestedAttribute generateReqAuthnAttributeSimple(final EIDASSAMLEngine engine,
	    final String name, final String friendlyName,
	    final String isRequired, final List<String> value) {
	LOG.debug("Generate the requested attribute.");

	final RequestedAttribute requested = (RequestedAttribute) SAMLEngineUtils
		.createSamlObject(RequestedAttribute.DEF_ELEMENT_NAME);
	requested.setName(name);
	requested.setNameFormat(RequestedAttribute.URI_REFERENCE);

	requested.setFriendlyName(friendlyName);

	requested.setIsRequired(isRequired);
	generateDocument(engine, name, value, requested.getAttributeValues());
	// The value is optional in an authentication request.

	return requested;
    }

	public static void generateDocument(final EIDASSAMLEngine engine, final String name, List<String> value, List<XMLObject> attributeValues){
		if (!value.isEmpty()) {
			final String nameSpace = engine.getExtensionProcessor().getFormat().getAssertionNS();
			final String prefix=engine.getExtensionProcessor().getFormat().getAssertionPrefix();
			for (int nextValue = 0; nextValue < value.size(); nextValue++) {
				final String valor = value.get(nextValue);
				if (StringUtils.isNotBlank(valor)) {

					if(!(engine.getExtensionProcessor().getFormat().getBaseURI()+"signedDoc").equals(name)){

						// Create the attribute statement
						final XSAny attrValue = (XSAny) SAMLEngineUtils
								.createSamlObject(
										new QName(nameSpace, "AttributeValue", prefix),
										XSAny.TYPE_NAME);

						attrValue.setTextContent(valor.trim());
						attributeValues.add(attrValue);

					}else{
						parseSignedDoc(attributeValues, nameSpace, prefix, valor);

					}


				}
			}
		}

	}

	private static void parseSignedDoc(List<XMLObject> attributeValues, String nameSpace, String prefix, String value){
		DocumentBuilderFactory domFactory = EIDASSAMLEngine.newDocumentBuilderFactory();
		domFactory.setNamespaceAware(true);
		Document document = null;
		DocumentBuilder builder;

		// Parse the signedDoc value into an XML DOM Document
		try {
			builder = domFactory.newDocumentBuilder();
			InputStream is;
			is = new ByteArrayInputStream(value.trim().getBytes("UTF-8"));
			document = builder.parse(is);
			is.close();
		} catch (SAXException e1) {
			LOG.info("ERROR : SAX Error while parsing signModule attribute", e1.getMessage());
			LOG.debug("ERROR : SAX Error while parsing signModule attribute", e1);
			throw new EIDASSAMLEngineRuntimeException(e1);
		} catch (ParserConfigurationException e2) {
			LOG.info("ERROR : Parser Configuration Error while parsing signModule attribute", e2.getMessage());
			LOG.debug("ERROR : Parser Configuration Error while parsing signModule attribute", e2);
			throw new EIDASSAMLEngineRuntimeException(e2);
		} catch (UnsupportedEncodingException e3) {
			LOG.info("ERROR : Unsupported encoding Error while parsing signModule attribute", e3.getMessage());
			LOG.debug("ERROR : Unsupported encoding Error while parsing signModule attribute", e3);
			throw new EIDASSAMLEngineRuntimeException(e3);
		} catch (IOException e4) {
			LOG.info("ERROR : IO Error while parsing signModule attribute", e4.getMessage());
			LOG.debug("ERROR : IO Error while parsing signModule attribute", e4);
			throw new EIDASSAMLEngineRuntimeException(e4);
		}

		// Create the XML statement(this will be overwritten with the previous DOM structure)
		final XSAny xmlValue = (XSAny) SAMLEngineUtils
				.createSamlObject(
						new QName(nameSpace,"XMLValue", prefix),
						XSAny.TYPE_NAME);

		//Set the signedDoc XML content to this element
		xmlValue.setDOM(document.getDocumentElement());

		// Create the attribute statement
		final XSAny attrValue = (XSAny) SAMLEngineUtils
				.createSamlObject(
						new QName(nameSpace, "AttributeValue", prefix),
						XSAny.TYPE_NAME);

		//Add previous signedDocXML to the AttributeValue Element
		attrValue.getUnknownXMLObjects().add(xmlValue);

		attributeValues.add(attrValue);
	}
    /**
     * Generate response.
     *
     * @param identifier the identifier
     * @param issueInstant the issue instant
     * @param status the status
     *
     * @return the response
     */
    public static Response generateResponse(
	    final String identifier, final DateTime issueInstant,
	    final Status status) {
	final Response response = (Response) SAMLEngineUtils
		.createSamlObject(Response.DEFAULT_ELEMENT_NAME);
	response.setID(identifier);
	response.setIssueInstant(issueInstant);
	response.setStatus(status);
	return response;
    }

    /**
     * Method that generates a SAML Authentication Request basing on the
     * provided information.
     *
     * @param identifier the identifier
     * @param version the version
     * @param issueInstant the issue instant
     *
     * @return the authentication request
     */
    public static AuthnRequest generateSAMLAuthnRequest(final String identifier,
	    final SAMLVersion version, final DateTime issueInstant) {
	LOG.debug("Generate basic authentication request.");
	final AuthnRequest authnRequest = (AuthnRequest) SAMLEngineUtils
		.createSamlObject(AuthnRequest.DEFAULT_ELEMENT_NAME);

	authnRequest.setID(identifier);
	authnRequest.setVersion(version);
	authnRequest.setIssueInstant(issueInstant);
	return authnRequest;
    }

    /**
     * Generate service provider application.
     *
     * @param spApplication the service provider application
     *
     * @return the sP application
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static SPApplication generateSPApplication(final String spApplication)
	    throws EIDASSAMLEngineException {
	LOG.debug("Generate SPApplication.");

	final SPApplication applicationAttr = (SPApplication) SAMLEngineUtils
		.createSamlObject(SPApplication.DEF_ELEMENT_NAME);
	applicationAttr.setSPApplication(spApplication);
	return applicationAttr;
    }

    /**
     * Generate service provider country.
     *
     * @param spCountry the service provider country
     *
     * @return the service provider country
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static SPCountry generateSPCountry(final String spCountry)
	    throws EIDASSAMLEngineException {
	LOG.debug("Generate SPApplication.");

	final SPCountry countryAttribute = (SPCountry) SAMLEngineUtils
		.createSamlObject(SPCountry.DEF_ELEMENT_NAME);
	countryAttribute.setSPCountry(spCountry);
	return countryAttribute;
    }

    /**
     * Generate service provider institution.
     *
     * @param spInstitution the service provider institution
     *
     * @return the service provider institution
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static SPInstitution generateSPInstitution(final String spInstitution)
	    throws EIDASSAMLEngineException {
	LOG.debug("Generate SPInstitution.");

	final SPInstitution institutionAttr = (SPInstitution) SAMLEngineUtils
		.createSamlObject(SPInstitution.DEF_ELEMENT_NAME);
	institutionAttr.setSPInstitution(spInstitution);
	return institutionAttr;
    }

    /**
     * Generate service provider sector.
     *
     * @param spSector the service provider sector
     *
     * @return the service provider sector
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static SPSector generateSPSector(final String spSector)
	    throws EIDASSAMLEngineException {
	LOG.debug("Generate SPSector.");

	final SPSector sectorAttribute = (SPSector) SAMLEngineUtils
		.createSamlObject(SPSector.DEF_ELEMENT_NAME);
	sectorAttribute.setSPSector(spSector);
	return sectorAttribute;
    }

    /**
     * Generate status.
     *
     * @param statusCode the status code
     *
     * @return the status
     */
    public static Status generateStatus(final StatusCode statusCode) {
	final Status status = (Status) SAMLEngineUtils
		.createSamlObject(Status.DEFAULT_ELEMENT_NAME);
	status.setStatusCode(statusCode);
	return status;
    }

    /**
     * Generate status code.
     *
     * @param value the value
     *
     * @return the status code
     */
    public static StatusCode generateStatusCode(final String value) {
	final StatusCode statusCode = (StatusCode) SAMLEngineUtils
		.createSamlObject(StatusCode.DEFAULT_ELEMENT_NAME);
	statusCode.setValue(value);
	return statusCode;
    }


    /**
     * Generate status message.
     *
     * @param message the message
     *
     * @return the status message
     */
    public static StatusMessage generateStatusMessage(final String message) {
	final StatusMessage statusMessage = (StatusMessage) SAMLEngineUtils
		.createSamlObject(StatusMessage.DEFAULT_ELEMENT_NAME);
	statusMessage.setMessage(message);
	return statusMessage;
    }

    /**
     * Generate subject.
     *
     * @return the subject
     */
    public static Subject generateSubject() {
	return (Subject) SAMLEngineUtils
		.createSamlObject(Subject.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Generate subject confirmation.
     *
     * @param method the method
     * @param data the data
     *
     * @return the subject confirmation
     */
    public static SubjectConfirmation generateSubjectConfirmation(
	    final String method, final SubjectConfirmationData data) {
	final SubjectConfirmation subjectConf = (SubjectConfirmation) Configuration
		.getBuilderFactory().getBuilder(
			SubjectConfirmation.DEFAULT_ELEMENT_NAME).buildObject(
			SubjectConfirmation.DEFAULT_ELEMENT_NAME);

	subjectConf.setMethod(method);

	subjectConf.setSubjectConfirmationData(data);

	return subjectConf;
    }


    /**
     * Generate subject confirmation data.
     *
     * @param notOnOrAfter the not on or after
     * @param recipient the recipient
     * @param inResponseTo the in response to
     *
     * @return the subject confirmation data
     */
    public static SubjectConfirmationData generateSubjectConfirmationData(
	    final DateTime notOnOrAfter, final String recipient,
	    final String inResponseTo) {
	final SubjectConfirmationData subjectConfData = (SubjectConfirmationData) SAMLEngineUtils
		.createSamlObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
	subjectConfData.setNotOnOrAfter(notOnOrAfter);
	subjectConfData.setRecipient(recipient);
	subjectConfData.setInResponseTo(inResponseTo);
	return subjectConfData;
    }


    /**
     * Generate subject locality.
     *
     * @param address the address
     *
     * @return the subject locality
     */
    public static SubjectLocality generateSubjectLocality(final String address) {
	final SubjectLocality subjectLocality = (SubjectLocality) SAMLEngineUtils
		.createSamlObject(SubjectLocality.DEFAULT_ELEMENT_NAME);
	subjectLocality.setAddress(address);
	return subjectLocality;
    }




    /**
     * Method that returns the current time.
     *
     * @return the current time
     */
    public static DateTime getCurrentTime() {
	return new DateTime();
    }


    /**
     * Instantiates a new SAML engine utilities.
     */
    private SAMLEngineUtils() {
    }

	public static BasicSecurityConfiguration getEidasGlobalSecurityConfiguration(){
		return (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
	}

    public static String validateSigningAlgorithm(String signatureAlgorithmName){
        if (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256.equalsIgnoreCase(signatureAlgorithmName)){
            return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
        }else if( SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384.equalsIgnoreCase(signatureAlgorithmName)) {
            return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384;
        } else if (!SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512.equalsIgnoreCase(signatureAlgorithmName)) {
            LOG.info("BUSINESS EXCEPTION : Invalid signing algorithm, defaulting to ALGO_ID_SIGNATURE_RSA_SHA512");
        }
        return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
    }
    public static String validateDigestAlgorithm(String signatureAlgorithmName){
        if (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256.equalsIgnoreCase(signatureAlgorithmName)) {
            return SignatureConstants.ALGO_ID_DIGEST_SHA256;
        } else if (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384.equalsIgnoreCase(signatureAlgorithmName)) {
            return SignatureConstants.ALGO_ID_DIGEST_SHA384;
        }
        return SignatureConstants.ALGO_ID_DIGEST_SHA512;
    }

	/**
	 *
	 * @param certificate
	 * @param privateKey
	 * @return a credential based on the provided elements
	 */
	public static Credential createCredential(X509Certificate certificate, PrivateKey privateKey){
		final BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(certificate);
		credential.setPrivateKey(privateKey);
		return credential;
	}

	public static <T> T createSAMLObject(final Class<T> clazz) throws NoSuchFieldException, IllegalAccessException {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
		XMLObjectBuilder builder = builderFactory.getBuilder(defaultElementName);
		T object = (T)builder.buildObject(defaultElementName);

		return object;
	}

	/**
	 *
	 * @param encryptionKeyStore
	 * @param serialNumber
	 * @param issuer
	 * @param keyPassword
	 * @return the credential of the private key of the certificate having the given serialnumber and issuer
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws SAMLEngineException
	 */


	public static Credential getCredential(KeyStore encryptionKeyStore, String serialNumber, String issuer, char [] keyPassword) throws NoSuchAlgorithmException,KeyStoreException,UnrecoverableKeyException,SAMLEngineException {
		CertificateAliasPair pair = getCertificatePair(encryptionKeyStore, serialNumber, issuer);
		final PrivateKey privateKey = (PrivateKey) encryptionKeyStore.getKey(pair.getAlias(), keyPassword);
		return SAMLEngineUtils.createCredential(pair.getCertificate(), privateKey);
	}

	public static Credential getEncryptionCredential(KeyStore encryptionKeyStore, String serialNumber, String issuer) throws NoSuchAlgorithmException,KeyStoreException,UnrecoverableKeyException,SAMLEngineException {
		CertificateAliasPair pair = getCertificatePair(encryptionKeyStore, serialNumber, issuer);
		// Create basic credential and set the EntityCertificate
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(pair.getCertificate());
		return credential;
	}

	/**
	 *
	 * @param keystore
	 * @param serialNumber
	 * @param issuer
	 * @return a certificate/alias pair from the keystore, having the given issuer and serialNumber
	 * @throws KeyStoreException
	 * @throws SAMLEngineException
	 */
	public static CertificateAliasPair getCertificatePair(KeyStore keystore, String serialNumber, String issuer ) throws KeyStoreException, SAMLEngineException{
		String alias = null;
		String aliasCert;
		X509Certificate certificate;
		boolean find = false;

		for (final Enumeration<String> e = keystore.aliases(); e
				.hasMoreElements() && !find; ) {
			aliasCert = e.nextElement();
			certificate = (X509Certificate) keystore.getCertificate(aliasCert);

			final String serialNum = certificate.getSerialNumber().toString(16);

			Principal p = certificate.getIssuerDN();
			String name = p.getName();

			X500Name issuerDN = new X500Name(name);
			X500Name issuerDNConf = new X500Name(issuer);

			if (serialNum.equalsIgnoreCase(serialNumber) && X500PrincipalUtil.principalEquals(issuerDN, issuerDNConf)) {
				alias = aliasCert;
				find = true;
			}
		}
		if (!find) {
			throw new SAMLEngineException("Certificate "+issuer+"/"+serialNumber+" cannot be found in keystore ");
		}
		certificate = (X509Certificate) keystore.getCertificate(alias);
		return new CertificateAliasPair(certificate, alias);

	}

	public static void checkTrust(Credential entityX509Cred, List<Credential> trustCred) throws SAMLEngineException{
		final ExplicitKeyTrustEvaluator keyTrustEvaluator = new ExplicitKeyTrustEvaluator();
		LOG.debug(entityX509Cred.getEntityId());
		if(entityX509Cred instanceof BasicX509Credential) {
			LOG.debug(((BasicX509Credential)entityX509Cred).getEntityCertificate().getIssuerDN().getName());
			LOG.debug("" + ((BasicX509Credential)entityX509Cred).getEntityCertificate().getNotAfter());
			LOG.debug("" + ((BasicX509Credential)entityX509Cred).getEntityCertificate().getSerialNumber());
		}
		if(!keyTrustEvaluator.validate(entityX509Cred,trustCred)) {
			throw new SAMLEngineException(EIDASErrors.SAML_ENGINE_UNTRUSTED_CERTIFICATE.errorCode(),EIDASErrors.SAML_ENGINE_UNTRUSTED_CERTIFICATE.errorMessage());
		}
	}

	public static Credential getKeyCredential(SAMLEngineModuleI module, KeyInfo keyInfo) throws SAMLEngineException{
		Credential credential;
		try {
			final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo.getX509Datas().get(0).getX509Certificates().get(0);

			final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
			final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
			final X509Certificate cert = (X509Certificate) certFact.generateCertificate(bis);

			credential = new BasicX509Credential();
			((BasicX509Credential) credential).setEntityCertificate(cert);
			if(module!=null){
				module.checkCertificateIssuer(cert);
				module.checkCertificateValidityPeriod(cert);
			}
		}catch(CertificateException ce){
			throw new SAMLEngineException(EIDASErrors.SAML_ENGINE_INVALID_CERTIFICATE.errorCode(),EIDASErrors.SAML_ENGINE_INVALID_CERTIFICATE.errorMessage(),ce);
		}
		return credential;
	}
	/**
	 * @param cert
	 * @return true when the certificate is self signed
	 */
	public static boolean isCertificateSelfSigned(X509Certificate cert) {
		try {
			PublicKey publicKey = cert.getPublicKey();
			cert.verify(publicKey);
			return true;
		} catch (java.security.SignatureException sigEx) {
			LOG.info("ERROR : SignatureException {}", sigEx.getMessage());
			LOG.debug("ERROR : SignatureException {}", sigEx);
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key --> not self-signed
			LOG.info("ERROR : InvalidKeyException {}", keyEx.getMessage());
			LOG.debug("ERROR : InvalidKeyException {}", keyEx);
			return false;
		} catch (CertificateException certExc) {
			LOG.info("ERROR : CertificateException {}", certExc.getMessage());
			LOG.debug("ERROR : CertificateException {}", certExc);
			return false;
		} catch (NoSuchAlgorithmException nsaExc) {
			LOG.info("ERROR : Bad algorithm: " + nsaExc.getMessage());
			LOG.debug("ERROR : Bad algorithm: " + nsaExc);
			return false;
		} catch (NoSuchProviderException nspExc) {
			LOG.info("ERROR : Bad provider: " + nspExc.getMessage());
			LOG.debug("ERROR : Bad provider: " + nspExc);
			return false;
		}
	}

	public static List<Credential> getListOfCredential(KeyStore keyStore) throws SAMLEngineException{
		final List<Credential> trustCred = new ArrayList<Credential>();
		try {
			String aliasCert = null;
			X509Certificate certificate;
			for (final Enumeration<String> e = keyStore.aliases(); e.hasMoreElements(); ) {
				aliasCert = e.nextElement();
				final BasicX509Credential credential = new BasicX509Credential();
				certificate = (X509Certificate) keyStore.getCertificate(aliasCert);
				credential.setEntityCertificate(certificate);
				trustCred.add(credential);
			}
		}catch (KeyStoreException e) {
			LOG.warn("ERROR : KeyStoreException.", e.getMessage());
			LOG.debug("ERROR : KeyStoreException.", e);
			throw new SAMLEngineException(e);
		}
		return trustCred;

	}

	public static void checkTrust(Credential entityX509Cred, KeyStore trustStore) throws SAMLEngineException{
		checkTrust(entityX509Cred, getListOfCredential(trustStore));
	}

	/**
	 * validates a metadata entitydescriptor's signature against a trustkeystore
	 * @param ed
	 * @param trustKeyStore
	 * @throws SAMLEngineException
	 */
	public static void validateEntityDescriptorSignature(SignableXMLObject ed, KeyStore trustKeyStore) throws SAMLEngineException{
		if(ed ==null){
			throw new SAMLEngineException("invalid entity descriptor");
		}
		try{
			SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
			org.opensaml.xml.signature.Signature signature=ed.getSignature();
			sigProfValidator.validate(signature);
			//check that EntityDescriptor matches the signature
			final KeyInfo keyInfo = ed.getSignature().getKeyInfo();

			final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo.getX509Datas().get(0).getX509Certificates().get(0);

			final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
			final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
			final X509Certificate cert = (X509Certificate) certFact.generateCertificate(bis);

			final BasicX509Credential entityX509Cred = new BasicX509Credential();
			entityX509Cred.setEntityCertificate(cert);
			final SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
            sigValidator.validate(signature);
			if(trustKeyStore!=null) {
				SAMLEngineUtils.checkTrust(entityX509Cred, trustKeyStore);
			}
		}catch(ValidationException exc){
			throw new SAMLEngineException(EIDASErrors.INVALID_SIGNATURE_ALGORITHM.errorCode(), exc);
		}catch(CertificateException exc){
			throw new SAMLEngineException(EIDASErrors.INVALID_SIGNATURE_ALGORITHM.errorCode(), exc);
		}

	}
	/**
	 * validates a metadata entitydescriptor's signature against a trustkeystore
	 * @param ed
	 * @param samlEngine
	 * @throws SAMLEngineException
	 */
	public static void validateEntityDescriptorSignature(SignableXMLObject ed, EIDASSAMLEngine samlEngine) throws SAMLEngineException{
		if(ed ==null || samlEngine==null){
			throw new SAMLEngineException("invalid metadata context");
		}
		validateEntityDescriptorSignature(ed, samlEngine.getSigner().getTrustStore());
	}

	/**
	 * identified whether a request is eIDAS format or not(ie Stork format)
	 * @param authRequest
	 * @return
	 */
	public static boolean isEidasFormat(EIDASAuthnRequest authRequest){
		if(authRequest==null || authRequest.getPersonalAttributeList()==null){
			return false;
		}
		for(PersonalAttribute pa:authRequest.getPersonalAttributeList()){
			if(EIDASAttributes.getAttributeType(pa.getFullName())!=null){
				return true;
			}
		}
		return false;
	}

	private static final String ALLOWED_METADATA_SCHEMES[]={"https://", "http://"};

	/**
	 * validates the issuer to be an url of a known scheme
	 * @param value
	 * @return the validated value
	 * @throws SAMLEngineException
	 */
	public static String getValidIssuerValue(String value) throws EIDASSAMLEngineException{
		if(value!=null){
			for(String scheme:ALLOWED_METADATA_SCHEMES){
				if(value.toLowerCase().startsWith(scheme)){
					return value;
				}
			}
		}
		LOG.error("CONFIGURATION ERROR - Issuer error, configuration entry "+ value + " is not valid (HTTP and HTTPS are the only metadata scheme are supported)");
		throw new EIDASSAMLEngineException(EIDASErrors.SAML_ENGINE_INVALID_METADATA.errorCode(), EIDASErrors.SAML_ENGINE_INVALID_METADATA.errorMessage());
	}

	/**
	 * @param binding SAML binding
	 * @return http method(either POST or GET)
	 */
	public static String getBindingMethod(String binding){
		if(SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding)) {
			return EIDASAuthnRequest.BINDING_REDIRECT;
		}else {
			return EIDASAuthnRequest.BINDING_POST;
		}
	}

	/**
	 * maps saml supported values for comparison type to those in opensaml
	 * @param loaCompareType
	 * @return
	 */
	public static AuthnContextComparisonTypeEnumeration getAuthnCtxtComparisonType(EidasLoaCompareType loaCompareType){
		return AuthnContextComparisonTypeEnumeration.MINIMUM;
	}

    /**
     * return the service LoA of a node
     * @param idp
     * @return
     */
    public static String getServiceLoA(EntityDescriptor idp){
        String retrievedLoA="";
        if(idp==null){
            return retrievedLoA;
        }
        for(XMLObject xmlObj:idp.getExtensions().getUnknownXMLObjects()){
            if(xmlObj instanceof EntityAttributes ){
                EntityAttributes eas = (EntityAttributes)xmlObj;
                for(Attribute attr:eas.getAttributes()){
                    if(EidasConstants.LEVEL_OF_ASSURANCE_NAME.equalsIgnoreCase(attr.getName()) &&
                            !attr.getAttributeValues().isEmpty()){
                        XSString val= (XSString)attr.getAttributeValues().get(0);
                        retrievedLoA=val.getValue();
                        break;
                    }
                }
                if(!StringUtils.isEmpty(retrievedLoA)){
                    break;
                }
            }
        }
        return retrievedLoA;
    }

    /**
    *
    * @param xmlObj
    * @return a string containing the xml representation of the entityDescriptor
    */
   public static String serializeObject(XMLObject xmlObj){
       StringWriter stringWriter = new StringWriter();
       String stringRepresentation="";
       try{
           DocumentBuilder builder;
           DocumentBuilderFactory factory = DocumentBuilderFactoryUtil.getSecureDocumentBuilderFactory();

           builder = factory.newDocumentBuilder();
           Document document = builder.newDocument();
           Marshaller out = Configuration.getMarshallerFactory().getMarshaller(xmlObj);
           out.marshall(xmlObj, document);

           Transformer transformer = TransformerFactory.newInstance().newTransformer();
           StreamResult streamResult = new StreamResult(stringWriter);
           DOMSource source = new DOMSource(document);
           transformer.transform(source, streamResult);
       }catch(ParserConfigurationException pce){
           LOG.info("ERROR : parser error", pce.getMessage());
           LOG.debug("ERROR : parser error", pce);
       }catch(TransformerConfigurationException tce ){
           LOG.info("ERROR : transformer configuration error", tce.getMessage());
           LOG.debug("ERROR : transformer configuration error", tce);
       }catch(TransformerException te){
           LOG.info("ERROR : transformer error", te.getMessage());
           LOG.debug("ERROR : transformer error", te);
       }catch (MarshallingException me) {
           LOG.info("ERROR : marshalling error", me.getMessage());
           LOG.debug("ERROR : marshalling error", me);
       }finally{
           try{
               stringWriter.close();
               stringRepresentation = stringWriter.toString();
           }catch(IOException ioe){
               LOG.warn("ERROR when closing the marshalling stream {}", ioe);
           }
       }
       return stringRepresentation;
   }

	public static boolean isErrorSamlResponse(Response response) {
		return response !=null && !StatusCode.SUCCESS_URI.equals(response.getStatus().getStatusCode().getValue());
	}

	private static final String NO_ASSERTION="no assertion found";
	private static final String ASSERTION_XPATH="//*[local-name()='Assertion']";

	/**
	 *
	 * @param samlMsg the saml response as a string
	 * @return a string representing the Assertion
	 */
	public static String extractAssertionAsString(String samlMsg){
		String assertion=NO_ASSERTION;
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(samlMsg)));

			XPath xPath = XPathFactory.newInstance().newXPath();
			Node node = (Node) xPath.evaluate(ASSERTION_XPATH, doc, XPathConstants.NODE);
			if(node!=null) {
				assertion = domnodeToString(node);
			}
		}catch(ParserConfigurationException pce){
			LOG.error("cannot parse response {}", pce);
		}catch(SAXException saxe){
			LOG.error("cannot parse response {}", saxe);

		}catch(IOException ioe){
			LOG.error("cannot parse response {}", ioe);

		}catch(XPathExpressionException xpathe){
			LOG.error("cannot find the assertion {}", xpathe);

		}catch(TransformerException trfe){
			LOG.error("cannot output the assertion {}", trfe);

		}

		return assertion;
	}

	private static String domnodeToString(Node node)
			throws TransformerException
	{
		StringWriter buf = new StringWriter();
		Transformer xForm = TransformerFactory.newInstance().newTransformer();
		xForm.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xForm.transform(new DOMSource(node), new StreamResult(buf));
		return(buf.toString());
	}

}
