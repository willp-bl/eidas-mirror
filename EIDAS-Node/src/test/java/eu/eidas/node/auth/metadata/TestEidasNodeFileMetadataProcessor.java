package eu.eidas.node.auth.metadata;

import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.configuration.SAMLBootstrap;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.node.auth.metadata.NODEFileMetadataProcessor;
import eu.eidas.node.auth.util.tests.FileUtils;

import org.junit.*;
import org.junit.runners.MethodSorters;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.FileSystemUtils;

import java.io.File;
import java.util.List;



import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

@FixMethodOrder(MethodSorters.JVM)
public class TestEidasNodeFileMetadataProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestEidasNodeFileMetadataProcessor.class.getName());

    private static final String FILEREPO_DIR_READ="src/test/resources/EntityDescriptors2/";
    private static final String FILEREPO_DIR_WRITE1="target/test/EntityDescriptors1/";
    private static final String FILEREPO_DIR_WRITE2="target/test/EntityDescriptors2/";
    private static final String FILEREPO_DIR_WRITE_EMPTY="target/test/EntityDescriptorsEmpty/";
    private static final String FILEREPO_DIR_READ_UPD="src/test/resources/EntityDescriptors1/";
    private static final String FILEREPO_DIR_READ_COMBO="src/test/resources/EntityDescriptors3/";
    private static final String FILEREPO_DIR_WRITE3="target/test/EntityDescriptors3/";
    private EIDASSAMLEngine getEngine() {
        EIDASSAMLEngine engine = null;
        try {
            engine = EIDASSAMLEngine.createSAMLEngine("METADATA");
            engine.setExtensionProcessor(new EidasExtensionProcessor());
        }catch (EIDASSAMLEngineException exc){
            assertTrue(false);
        }
        return engine;
    }

    @BeforeClass
    public static void setUp(){
        LOGGER.debug("initializing directory "+FILEREPO_DIR_WRITE1);
        initWorkFolder(FILEREPO_DIR_READ, FILEREPO_DIR_WRITE1);
        LOGGER.debug("initializing directory "+FILEREPO_DIR_WRITE2);
        initWorkFolder(FILEREPO_DIR_READ, FILEREPO_DIR_WRITE2);
        new File(FILEREPO_DIR_WRITE_EMPTY).mkdirs();
        initWorkFolder(FILEREPO_DIR_READ_COMBO, FILEREPO_DIR_WRITE3);
        try {
        	SAMLBootstrap.bootstrap();
        }catch (ConfigurationException ce){
            assertTrue("opensaml configuration exception", false);
        }
    }
    private static void initWorkFolder(String sourceFolder, String folderName){
        File sampleNodeRepo=new File(folderName);
        FileSystemUtils.deleteRecursively(sampleNodeRepo);
        sampleNodeRepo.mkdirs();
        FileUtils.copyFile(new File(sourceFolder), sampleNodeRepo);
    }
    @AfterClass
    public static void removeDir(){
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE1));
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE2));
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE3));
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE_EMPTY));
    }

    @Test
    public void testGetEntityDescriptorsEmpty(){
        NODEFileMetadataProcessor processor=new NODEFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE_EMPTY);
        List<EntityDescriptorContainer> list = processor.getEntityDescriptors();
        assertTrue(list.isEmpty());
    }
    @Test
    public void testGetEntityDescriptors(){
        NODEFileMetadataProcessor processor=new NODEFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE1);
        List<EntityDescriptorContainer> list = processor.getEntityDescriptors();
        assertTrue(list.size()==2);
        EntityDescriptor ed1=list.get(0).getEntityDescriptors().get(0);
        assertNotNull(ed1);
        assertTrue(!ed1.isValid());
        EntityDescriptor ed2=list.get(1).getEntityDescriptors().get(0);
        assertNotNull(ed2);
        assertTrue(ed2.isValid());
    }

    @Test
    public void testUpdateEntityDescriptors(){
        NODEFileMetadataProcessor processor=new NODEFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE2);
        List<EntityDescriptorContainer> list = processor.getEntityDescriptors();
        assertTrue(list.size()==2);
        File sampleNodeRepo=new File(FILEREPO_DIR_WRITE2);
        FileUtils.copyFile(new File(FILEREPO_DIR_READ_UPD), sampleNodeRepo);
        try{
            Thread.sleep(3000);
        }catch(InterruptedException ie){
            fail("got interrupted exception");
        }
        list = processor.getEntityDescriptors();
        assertTrue(list.size()==3);
    }

    @Test
    public void testCombo(){
        NODEFileMetadataProcessor processor=new NODEFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE3);
        List<EntityDescriptorContainer> list = processor.getEntityDescriptors();
        assertTrue(list.size()==2);
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        EntitiesDescriptor eds = (EntitiesDescriptor)builderFactory.getBuilder(EntitiesDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
        for(EntityDescriptorContainer edc:list){
        	eds.getEntityDescriptors().addAll(edc.getEntityDescriptors());
        }
        String s=null;
        try{
        	s=new String(getEngine().signAndMarshallEntitiesDescriptor(eds));
        }catch(SAMLEngineException ee){
        	fail("cannot sign");
        }
        //String s=SAMLEngineUtils.serializeObject(eds);
        assertFalse(s.isEmpty());
        
		EntityDescriptorContainer edc=new MetadataGenerator().deserializeEntityDescriptor(s);

		try{
			SAMLEngineUtils.validateEntityDescriptorSignature(edc.getEntitiesDescriptor(), getEngine());
		}catch(SAMLEngineException se){
			fail("signature does not validate");
		}
        
    }

}
