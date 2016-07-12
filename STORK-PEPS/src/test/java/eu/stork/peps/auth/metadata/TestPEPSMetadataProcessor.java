package eu.stork.peps.auth.metadata;

import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.util.tests.FileUtils;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.init.StorkSAMLEngineFactory;
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

public class TestPEPSMetadataProcessor {
    private static final String FILEREPO_DIR_READ="src/test/resources/EntityDescriptors1/";
    private static final String FILEREPO_DIR_WRITE="target/test/EntityDescriptors/";
    private static final String FILEREPO_DIR_WRITE_EMPTY="target/test/EntityDescriptorsEmpty/";
    private static final String ENTITY_ID="http://peps:8888/PEPS/SPEPSMetadata";
    private static final String FILEREPO_SIGNATURE="src/test/resources/SignatureCheck/";
    private static final String SPEPS_ENTITY_ID ="http://peps:8888/PEPS/SPEPSMetadata";
    @Before
    public void setUp(){
        File samplePepsRepo=new File(FILEREPO_DIR_WRITE);
        FileSystemUtils.deleteRecursively(samplePepsRepo);
        samplePepsRepo.mkdirs();
        FileUtils.copyFile(new File(FILEREPO_DIR_READ), samplePepsRepo);
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
        PEPSMetadataProcessor processor=new PEPSMetadataProcessor();
        processor.setFileMetadataLoader(new PEPSFileMetadataProcessor());
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
        PEPSMetadataProcessor processor=new PEPSMetadataProcessor();
        processor.setFileMetadataLoader(new PEPSFileMetadataProcessor());
        processor.getFileMetadataLoader().setRepositoryPath(FILEREPO_SIGNATURE);
        processor.setCache(new SimpleMetadataCaching());
        processor.initProcessor();
        EntityDescriptor ed=null;
        try{
            ed = processor.getEntityDescriptor(SPEPS_ENTITY_ID);
            assertNotNull(ed);
            STORKSAMLEngine engine = new StorkSAMLEngineFactory().getEngine("METADATA", null);
            processor.checkValidMetadataSignature(SPEPS_ENTITY_ID, engine);
        }catch(SAMLEngineException exc){
            fail("got error checking the signature: "+exc);
        }
    }
}
