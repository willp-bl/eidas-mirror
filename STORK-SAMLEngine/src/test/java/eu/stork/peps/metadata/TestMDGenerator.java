package eu.stork.peps.metadata;
import eu.stork.peps.auth.engine.SAMLEngineUtils;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.X500PrincipalUtil;
import eu.stork.peps.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.stork.peps.auth.engine.metadata.MetadataConfigParams;
import eu.stork.peps.auth.engine.metadata.MetadataGenerator;
import eu.stork.peps.configuration.SAMLBootstrap;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.*;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.junit.Assert.*;

/**
 * testing MDGenerator
 */
@FixMethodOrder(MethodSorters.JVM)
public class TestMDGenerator {
    private static final String TEST_KEYSTORE_LOCATION="src/test/resources/keyStoreCountry1.jks";
    private static final String TEST_KEYSTORE_PASSWORD="local-demo";
    private static final String TEST_KEYSTORE_SERIALNUMBER="54D8A000";
    private static final String TEST_KEYSTORE_ISSUER="CN=local-demo-cert, OU=DIGIT, O=European Comission, L=Brussels, ST=Belgium, C=BE";
    private static final String TEST_SIGNATURE_ALGORITHM="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private static final String TEST_COUNTRY_NAME="Belgium";
    @Before
    public void setUp(){
        try {
            SAMLBootstrap.bootstrap();
        }catch (ConfigurationException ce){
            fail("SAML bootstrap error: "+ce);
        }
    }
    @After
    public void removeDir(){
    }
    @Test
    public void testCreateMetadata(){
        try {
            MetadataGenerator generator = new MetadataGenerator();
            MetadataConfigParams mcp=new MetadataConfigParams();
            generator.setConfigParams(mcp);
            mcp.setEntityID("entityID");
            generator.addSPRole();
            generator.addIDPRole();
            mcp.setAssertionConsumerUrl("http://localhost");
            mcp.setAuthnRequestsSigned(true);
            mcp.setWantAssertionsSigned(true);
            Signature spSignature=createSampleSignature();
            mcp.setSPSignature(spSignature);
            mcp.setIDPSignature(createSampleSignature());
            mcp.setEncryptionCredential(createTestCredential());
            mcp.setSigningCredential(createTestCredential());
            mcp.setCountryName(TEST_COUNTRY_NAME);
            String metadata = generator.generateMetadata();
            assertTrue(metadata != null && !metadata.isEmpty());
        }catch(Exception exc){
            assertTrue("exception caught :"+exc, false);
        }
    }
    private static STORKSAMLEngine engine = null;
//    private static STORKSAMLEngine engineO =null;
    static {
        try {
            engine = STORKSAMLEngine.createSTORKSAMLEngine("METADATATEST");
            engine.setExtensionProcessor(new EidasExtensionProcessor());
//            engineO = STORKSAMLEngine.createSTORKSAMLEngine("METADATATESTO");
        }catch (STORKSAMLEngineException exc){
            assertTrue(false);
        }
    }
    @Test
    public void testCreateMetadataWithSamlEngine(){
        try {
            MetadataGenerator generator = new MetadataGenerator();
            MetadataConfigParams mcp=new MetadataConfigParams();
            generator.setConfigParams(mcp);
            generator.initialize(engine);
            mcp.setEntityID("entityID");
            generator.addSPRole();
            generator.addIDPRole();
            mcp.setAssertionConsumerUrl("http://localhost");
            mcp.setAuthnRequestsSigned(true);
            mcp.setWantAssertionsSigned(true);
            mcp.setAssuranceLevel("http://eidas.europa.eu/LoA");
            mcp.setSpType("public");
            mcp.setDigestMethods("http://www.w3.org/2001/04/xmlenc#sha256");
            mcp.setSigningMethods("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
            String metadata = generator.generateMetadata();
            assertTrue(metadata != null && !metadata.isEmpty());

            //unmmarshal
            final UnmarshallerFactory unmarshallerFact = Configuration.getUnmarshallerFactory();

            final BasicParserPool ppMgr = STORKSAMLEngine.getNewBasicSecuredParserPool();

            // Parse SAMLToken
            Document document = ppMgr.parse(new ByteArrayInputStream(metadata.getBytes(Charset.forName("UTF-8"))));
            final Element root = document.getDocumentElement();
            Unmarshaller u=unmarshallerFact.getUnmarshaller(root);
            assertNotNull(u);
            EntityDescriptor ed = (EntityDescriptor)u.unmarshall(root);
            assertNotNull(ed);
            checkSignature(ed);
            checkSPSSO(ed);
        }catch(Exception exc){
            fail("exception caught :"+exc);
        }
    }

    private void checkSignature(EntityDescriptor ed) throws CertificateException, ValidationException{
        SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
        sigProfValidator.validate(ed.getSignature());
        //check that EntityDescriptor matches the signature
        final KeyInfo keyInfo = ed.getSignature().getKeyInfo();

        final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo.getX509Datas().get(0).getX509Certificates().get(0);

        final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
        final X509Certificate cert = (X509Certificate) certFact.generateCertificate(bis);

        final BasicX509Credential entityX509Cred = new BasicX509Credential();
        entityX509Cred.setEntityCertificate(cert);
        final SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
        sigValidator.validate(ed.getSignature());
    }


    private void checkSPSSO(EntityDescriptor ed) throws CertificateException, ValidationException{
        assertTrue(ed.getRoleDescriptors().size()==2);
        SPSSODescriptor spSSO=(SPSSODescriptor)ed.getRoleDescriptors().get(0);
        assertNotNull(spSSO);
        org.opensaml.xml.signature.X509Certificate xmlCert=spSSO.getKeyDescriptors().get(0).getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        assertNotNull(xmlCert);
        final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));
        final X509Certificate cert = (X509Certificate) certFact.generateCertificate(bis);

        final BasicX509Credential entityX509Cred = new BasicX509Credential();
        entityX509Cred.setEntityCertificate(cert);
        //check that the signature conforms to saml2
        SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
        sigProfValidator.validate(spSSO.getSignature());
        //check that spSSO matches the signature
        final SignatureValidator sigValidator = new SignatureValidator(entityX509Cred);
        sigValidator.validate(spSSO.getSignature());

    }

    Signature createSampleSignature(){
        Signature signature = null;
        try {
            Credential credential = createTestCredential();
            signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);

            signature.setSigningCredential(credential);

            signature.setSignatureAlgorithm(TEST_SIGNATURE_ALGORITHM);


            final SecurityConfiguration secConfiguration = SAMLEngineUtils.getStorkGlobalSecurityConfiguration();
            final NamedKeyInfoGeneratorManager keyInfoManager = secConfiguration.getKeyInfoGeneratorManager();
            final KeyInfoGeneratorManager keyInfoGenManager = keyInfoManager.getDefaultManager();
            final KeyInfoGeneratorFactory keyInfoGenFac = keyInfoGenManager.getFactory(credential);
            final KeyInfoGenerator keyInfoGenerator = keyInfoGenFac.newInstance();

            KeyInfo keyInfo = keyInfoGenerator.generate(credential);

            signature.setKeyInfo(keyInfo);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);


        }catch (org.opensaml.xml.security.SecurityException e) {
            fail("Security exception:" + e);
        }
        return signature;
    }

    private KeyStore loadTestKeystore(){
        KeyStore testKeyStore = null;
        FileInputStream fis=null;
        try {
            testKeyStore = KeyStore.getInstance("JKS");
            fis = new FileInputStream(TEST_KEYSTORE_LOCATION);

            testKeyStore.load(fis, TEST_KEYSTORE_PASSWORD.toCharArray());
        }catch(KeyStoreException kse){
            fail("KeystoreException: "+kse);
        }catch(FileNotFoundException fnfe){
            fail("FileNotFoundException: "+fnfe);
        }catch(NoSuchAlgorithmException nsae){
            fail("NoSuchAlgorithmException: "+nsae);
        }catch(CertificateException ce){
            fail("CertificateException: "+ce);
        }catch(IOException ioe){
            fail("IOException: "+ioe);
        }finally{
            try{
                if(fis!=null){
                    fis.close();
                }
            }catch (IOException ioe){
                fail("IOException closing FileInputStream: "+ioe);
            }
        }
        return testKeyStore;
    }
    private Credential createTestCredential(){
        Credential credential=null;
        try {
            final String serialNumber = TEST_KEYSTORE_SERIALNUMBER;
            final String issuer = TEST_KEYSTORE_ISSUER;

            String alias = null;
            String aliasCert;
            X509Certificate certificate;
            boolean find = false;
            KeyStore testKeyStore = loadTestKeystore();
            for (final Enumeration<String> e = testKeyStore.aliases(); e.hasMoreElements() && !find; ) {
                aliasCert = e.nextElement();
                certificate = (X509Certificate) testKeyStore.getCertificate(aliasCert);

                final String serialNum = certificate.getSerialNumber()
                        .toString(16);

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
                fail("Certificate cannot be found in keystore ");
            }
            certificate = (X509Certificate) testKeyStore.getCertificate(alias);

            final PrivateKey privateKey = (PrivateKey) testKeyStore.getKey(alias, TEST_KEYSTORE_PASSWORD.toCharArray());
            credential = SAMLEngineUtils.createCredential(certificate, privateKey);
        }catch (NoSuchAlgorithmException e) {
            fail("A 'xmldsig#rsa-sha1' cryptographic algorithm is requested but is not available in the environment: " + e);
        } catch (KeyStoreException e) {
            fail("Generic KeyStore exception:" + e);
        } catch (UnrecoverableKeyException e) {
            fail("UnrecoverableKey exception:" + e);
        }
        return credential;
    }
}
