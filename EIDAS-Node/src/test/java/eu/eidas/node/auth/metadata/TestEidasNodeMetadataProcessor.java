package eu.eidas.node.auth.metadata;

import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.node.auth.metadata.NODEFileMetadataProcessor;
import eu.eidas.node.auth.metadata.NODEMetadataProcessor;
import eu.eidas.node.auth.metadata.SimpleMetadataCaching;
import eu.eidas.node.auth.util.tests.FileUtils;
import eu.eidas.node.init.EidasSamlEngineFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.springframework.util.FileSystemUtils;

import java.io.File;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestEidasNodeMetadataProcessor {
    private static final String FILEREPO_DIR_READ="src/test/resources/EntityDescriptors1/";
    private static final String FILEREPO_DIR_WRITE="target/test/EntityDescriptors/";
    private static final String FILEREPO_DIR_WRITE_EMPTY="target/test/EntityDescriptorsEmpty/";
    private static final String ENTITY_ID="http://EidasNode:8888/EidasNode/ConnectorMetadata";
    private static final String FILEREPO_SIGNATURE="src/test/resources/SignatureCheck/";
    private static final String CONNECTOR_ENTITY_ID =ENTITY_ID;
    @Before
    public void setUp(){
        File sampleNodeRepo=new File(FILEREPO_DIR_WRITE);
        FileSystemUtils.deleteRecursively(sampleNodeRepo);
        sampleNodeRepo.mkdirs();
        FileUtils.copyFile(new File(FILEREPO_DIR_READ), sampleNodeRepo);
        new File(FILEREPO_DIR_WRITE_EMPTY).mkdirs();
        try {
            DefaultBootstrap.bootstrap();
        }catch (ConfigurationException ce){
            assertTrue("opensaml configuration exception", false);
        }
    }
    @After
    public void removeDir(){
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE));
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE_EMPTY));
    }

    @Test
    public void testgetEntityDescriptors(){
        NODEMetadataProcessor processor=new NODEMetadataProcessor();
        processor.setFileMetadataLoader(new NODEFileMetadataProcessor());
        processor.getFileMetadataLoader().setRepositoryPath(FILEREPO_DIR_WRITE);
        processor.setCache(new SimpleMetadataCaching());
        processor.initProcessor();
        EntityDescriptor ed=null;
        try{
            //expect exactly one expired entity descriptor
            ed = processor.getEntityDescriptor(ENTITY_ID);
            fail("expect exactly one expired entity descriptor");
        }catch(SAMLEngineException exc){
            assertTrue(ed==null);
        }
    }
    @Test
    public void testValidatesignature(){
        NODEMetadataProcessor processor=new NODEMetadataProcessor();
        processor.setFileMetadataLoader(new NODEFileMetadataProcessor());
        processor.getFileMetadataLoader().setRepositoryPath(FILEREPO_SIGNATURE);
        processor.setCache(new SimpleMetadataCaching());
        processor.initProcessor();
        EntityDescriptor ed=null;
        try{
            ed = processor.getEntityDescriptor(CONNECTOR_ENTITY_ID);
            assertNotNull(ed);
            EIDASSAMLEngine engine = new EidasSamlEngineFactory().getEngine("METADATA", null);
            processor.checkValidMetadataSignature(CONNECTOR_ENTITY_ID, engine);
        }catch(SAMLEngineException exc){
            fail("got error checking the signature: "+exc);
        }
    }
}
