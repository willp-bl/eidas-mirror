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
package eu.eidas.node.auth.metadata;

import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.node.auth.metadata.NODEFileMetadataProcessor;
import eu.eidas.node.auth.metadata.NODEMetadataProcessor;
import eu.eidas.node.auth.metadata.SimpleMetadataCaching;
import eu.eidas.node.init.EidasSamlEngineFactory;
import eu.eidas.node.utils.EidasNodeMetadataGenerator;
import eu.eidas.node.utils.PropertiesUtil;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.FileSystemUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Properties;

import static org.junit.Assert.*;

public class EidasNodeMetadataGeneratorTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestEidasNodeFileMetadataProcessor.class.getName());
    private static final String FILEREPO_DIR_WRITE="target/test/EntityDescriptors1/";
    private static final String ENTITY_ID="http://connectorasIdpurl";

    @BeforeClass
    public static void setUp(){
        LOGGER.debug("initializing directory " + FILEREPO_DIR_WRITE);
        new File(FILEREPO_DIR_WRITE).mkdirs();
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException ce) {
            assertTrue("opensaml configuration exception", false);
        }
    }
    @AfterClass
    public static void removeDir() {
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE));
    }

    private void putMetadataInFile(String fileName, String metadataContent){
        File f=new File(fileName);
        try {
            FileWriter fw = new FileWriter(f);
            fw.append(metadataContent);
            fw.close();
        }catch(IOException ioe){
            fail("error writing metadata contents: "+ioe);
        }
    }

    @Test
    public void testGenerateMetadataConnectorasIdP() throws Exception {
        EidasNodeMetadataGenerator generator = new EidasNodeMetadataGenerator();
        generator.setSamlConnectorIDP("METADATA");
        generator.setConnectorMetadataUrl(ENTITY_ID);
        generator.setSamlEngineFactory(new EidasSamlEngineFactory());
        generator.setConnectorCountry("CB");
        generator.setConnectorUrl(ENTITY_ID);

        String metadata = generator.generateConnectorMetadata();
        assertTrue(metadata.contains("<?xml"));

        putMetadataInFile(FILEREPO_DIR_WRITE+"/test.xml", metadata);
        NODEMetadataProcessor processor=new NODEMetadataProcessor();
        processor.setFileMetadataLoader(new NODEFileMetadataProcessor());
        processor.getFileMetadataLoader().setRepositoryPath(FILEREPO_DIR_WRITE);
        processor.setCache(new SimpleMetadataCaching());
        processor.initProcessor();
        EntityDescriptor ed=null;
        try{
            ed = processor.getEntityDescriptor(ENTITY_ID);
            assertTrue(ed.isValid());
        }catch(SAMLEngineException exc){
            fail("expect exactly one expired entity descriptor");
        }
    }
    private final static String CONTACT_SOURCE="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE properties SYSTEM \"http://java.sun.com/dtd/properties.dtd\">\n" +
            "<properties>" +
            "\t<entry key=\"connector.contact.support.email\">contact.support@eidas-connector.eu</entry>\n" +
            "\t<entry key=\"connector.contact.support.company\">eIDAS Connector Operator</entry>\n" +
            "\t<entry key=\"connector.contact.support.givenname\">John</entry>\n" +
            "\t<entry key=\"connector.contact.support.surname\">Doe</entry>\n" +
            "\t<entry key=\"connector.contact.support.phone\">+40 123456</entry>\n" +
            "\t<entry key=\"connector.contact.technical.email\">contact.technical@eidas-connector.eu</entry>\n" +
            "\t<entry key=\"connector.contact.technical.company\">eIDAS Connector Operator</entry>\n" +
            "\t<entry key=\"connector.contact.technical.givenname\">John</entry>\n" +
            "\t<entry key=\"connector.contact.technical.surname\">Doe</entry>\n" +
            "\t<entry key=\"connector.contact.technical.phone\">+41 123456</entry>\n" +
            "\t\t<!-- service-->\n" +
            "\t<entry key=\"service.contact.support.email\">contact.support@eidas-proxyservice.eu</entry>\n" +
            "\t<entry key=\"service.contact.support.company\">eIDAS ProxyService Operator</entry>\n" +
            "\t<entry key=\"service.contact.support.givenname\">John</entry>\n" +
            "\t<entry key=\"service.contact.support.surname\">Doe</entry>\n" +
            "\t<entry key=\"service.contact.support.phone\">+42 123456</entry>\n" +
            "\t<entry key=\"service.contact.technical.email\">contact.technical@eidas-proxyservice.eu</entry>\n" +
            "\t<entry key=\"service.contact.technical.company\">eIDAS ProxyService Operator</entry>\n" +
            "\t<entry key=\"service.contact.technical.givenname\">John</entry>\n" +
            "\t<entry key=\"service.contact.technical.surname\">Doe</entry>\n" +
            "\t<entry key=\"service.contact.technical.phone\">+43 123456</entry>\n" +
            "</properties>";
    private final static String CONTACT_SOURCE_INCOMPLETE="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE properties SYSTEM \"http://java.sun.com/dtd/properties.dtd\">\n" +
            "<properties>" +
            "\t<entry key=\"connector.contact.support.email\">contact.support@eidas-connector.eu</entry>\n" +
            "\t<entry key=\"connector.contact.support.company\">eIDAS Connector Operator</entry>\n" +
            "\t<entry key=\"connector.contact.support.givenname\">John</entry>\n" +
            "\t<entry key=\"connector.contact.support.surname\">Doe</entry>\n" +
            "\t<entry key=\"connector.contact.technical.email\">contact.technical@eidas-connector.eu</entry>\n" +
            "\t<entry key=\"connector.contact.technical.company\">eIDAS Connector Operator</entry>\n" +
            "\t<entry key=\"connector.contact.technical.givenname\">John</entry>\n" +
            "\t<entry key=\"connector.contact.technical.surname\">Doe</entry>\n" +
            "\t\t<!-- service-->\n" +
            "\t<entry key=\"service.contact.support.email\">contact.support@eidas-proxyservice.eu</entry>\n" +
            "\t<entry key=\"service.contact.support.company\">eIDAS ProxyService Operator</entry>\n" +
            "\t<entry key=\"service.contact.support.givenname\">John</entry>\n" +
            "\t<entry key=\"service.contact.support.phone\">+42 123456</entry>\n" +
            "\t<entry key=\"service.contact.technical.company\">eIDAS ProxyService Operator</entry>\n" +
            "\t<entry key=\"service.contact.technical.givenname\">John</entry>\n" +
            "\t<entry key=\"service.contact.technical.surname\">Doe</entry>\n" +
            "\t<entry key=\"service.contact.technical.phone\">+43 123456</entry>\n" +
            "</properties>";
    private static final String EXPECTED_METADATA_CONTACT="GivenName>John</";

    @Test
    public void testGenerateMetadataWithContacts() throws Exception {
        EidasNodeMetadataGenerator generator = new EidasNodeMetadataGenerator();
        generator.setSamlConnectorIDP("METADATA");
        generator.setConnectorMetadataUrl(ENTITY_ID);
        generator.setSamlEngineFactory(new EidasSamlEngineFactory());
        generator.setConnectorCountry("CB");
        generator.setConnectorUrl(ENTITY_ID);
        Properties contactProps=loadContactProps(CONTACT_SOURCE);
        generator.setNodeProps(contactProps);

        String metadata = generator.generateConnectorMetadata();
        assertTrue(metadata.contains("<?xml"));
        assertTrue(metadata.contains(EXPECTED_METADATA_CONTACT));

        contactProps=loadContactProps(CONTACT_SOURCE_INCOMPLETE);
        generator.setNodeProps(contactProps);

        metadata = generator.generateConnectorMetadata();
        assertTrue(metadata.contains("<?xml"));
        assertTrue(metadata.contains(EXPECTED_METADATA_CONTACT));
    }

    private Properties loadContactProps(String source){
        Properties props=new Properties();
        try {
            InputStream stream = new ByteArrayInputStream(source.getBytes(Charset.forName("UTF-8")));
            props.loadFromXML(stream);
        }catch(Exception exc){
            fail("cannot load properties "+exc);
        }
        return props;
    }
    

}