package eu.stork.peps.auth.metadata;

import eu.stork.peps.auth.util.tests.FileUtils;
import org.junit.*;
import org.junit.runners.MethodSorters;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.FileSystemUtils;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@FixMethodOrder(MethodSorters.JVM)
public class TestPEPSFileMetadataProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestPEPSFileMetadataProcessor.class.getName());

    private static final String FILEREPO_DIR_READ="src/test/resources/EntityDescriptors2/";
    private static final String FILEREPO_DIR_WRITE1="target/test/EntityDescriptors1/";
    private static final String FILEREPO_DIR_WRITE2="target/test/EntityDescriptors2/";
    private static final String FILEREPO_DIR_WRITE_EMPTY="target/test/EntityDescriptorsEmpty/";
    private static final String FILEREPO_DIR_READ_UPD="src/test/resources/EntityDescriptors1/";

    @BeforeClass
    public static void setUp(){
        LOGGER.debug("initializing directory "+FILEREPO_DIR_WRITE1);
        initWorkFolder(FILEREPO_DIR_WRITE1);
        LOGGER.debug("initializing directory "+FILEREPO_DIR_WRITE2);
        initWorkFolder(FILEREPO_DIR_WRITE2);
        new File(FILEREPO_DIR_WRITE_EMPTY).mkdirs();
        try {
            DefaultBootstrap.bootstrap();
        }catch (ConfigurationException ce){
            assertTrue("opensaml configuration exception", false);
        }
    }
    private static void initWorkFolder(String folderName){
        File samplePepsRepo=new File(folderName);
        FileSystemUtils.deleteRecursively(samplePepsRepo);
        samplePepsRepo.mkdirs();
        FileUtils.copyFile(new File(FILEREPO_DIR_READ), samplePepsRepo);
    }
    @AfterClass
    public static void removeDir(){
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE1));
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE2));
        FileSystemUtils.deleteRecursively(new File(FILEREPO_DIR_WRITE_EMPTY));
    }

    @Test
    public void testGetEntityDescriptorsEmpty(){
        PEPSFileMetadataProcessor processor=new PEPSFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE_EMPTY);
        List<EntityDescriptor> list = processor.getEntityDescriptors();
        assertTrue(list.isEmpty());
    }
    @Test
    public void testGetEntityDescriptors(){
        PEPSFileMetadataProcessor processor=new PEPSFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE1);
        List<EntityDescriptor> list = processor.getEntityDescriptors();
        assertTrue(list.size()==2);
        EntityDescriptor ed1=list.get(0);
        assertNotNull(ed1);
        assertTrue(!ed1.isValid());
        EntityDescriptor ed2=list.get(1);
        assertNotNull(ed2);
        assertTrue(ed2.isValid());
    }

    @Test
    public void testUpdateEntityDescriptors(){
        PEPSFileMetadataProcessor processor=new PEPSFileMetadataProcessor();
        processor.setRepositoryPath(FILEREPO_DIR_WRITE2);
        List<EntityDescriptor> list = processor.getEntityDescriptors();
        assertTrue(list.size()==2);
        File samplePepsRepo=new File(FILEREPO_DIR_WRITE2);
        FileUtils.copyFile(new File(FILEREPO_DIR_READ_UPD), samplePepsRepo);
        try{
            Thread.sleep(3000);
        }catch(InterruptedException ie){
            fail("got interrupted exception");
        }
        list = processor.getEntityDescriptors();
        assertTrue(list.size()==3);
    }

}
