package eu.stork;

import eu.stork.config.PEPSMasterConfiguration;
import eu.stork.config.impl.FileConfigurationRepository;
import eu.stork.config.peps.PEPSParameter;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.FileSystemUtils;

import java.io.*;

import static org.junit.Assert.*;

/**
 * example how this module can be integrated on a configuration reader side.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="/testcontext.xml")
@FixMethodOrder(MethodSorters.JVM)
public class TestIntegrationSample {
    private static final String FILEREPO_DIR="target/test/config/";
    private static final String FILEREPO_SOURCE_DIR="src/test/resources/config/";
    private static final String PARAM_NAME="speps.id";
    private static final String COUNTRY_VALUE="CB";
    private static final String NEW_COUNTRY_VALUE="OC";
    @Autowired
    PEPSMasterConfiguration pepsMasterConfiguration=null;

    @Before
    public void setUp(){
        java.io.File samplePepsRepo=new java.io.File(FILEREPO_DIR);
        FileSystemUtils.deleteRecursively(samplePepsRepo);
        samplePepsRepo.mkdirs();
        FileUtils.copyFile(new File(FILEREPO_SOURCE_DIR), new File(FILEREPO_DIR));
    }


    @Test
    public void testRead(){
        assertNotNull(pepsMasterConfiguration);
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration());
        ((FileConfigurationRepository)(pepsMasterConfiguration.getRepository())).getFileService().setRepositoryDir(FILEREPO_DIR);
        pepsMasterConfiguration.getPepsConfiguration().load();//loads peps parameters from PEPS.xml
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getMetadataProvider());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getMetadataProvider().getCategories().isEmpty());
    }

    @Test
    public void testWrite(){
        ((FileConfigurationRepository)(pepsMasterConfiguration.getRepository())).getFileService().setRepositoryDir(FILEREPO_DIR);
        pepsMasterConfiguration.getPepsConfiguration().load();//loads peps parameters from PEPS.xml
        pepsMasterConfiguration.getPepsConfiguration().getMetadataProvider().getCategories();
        assertEquals(pepsMasterConfiguration.getPepsConfiguration().getMetadataProvider().getMetadata(PARAM_NAME).getName(), PARAM_NAME);
        PEPSParameter param = pepsMasterConfiguration.getPepsConfiguration().getPepsParameters().get(PARAM_NAME);
        assertEquals(param.getValue(), COUNTRY_VALUE);
        param.setValue(NEW_COUNTRY_VALUE);
        pepsMasterConfiguration.getPepsConfiguration().save();
        checkFileIsChanged();
        param.setValue(COUNTRY_VALUE);
        pepsMasterConfiguration.getPepsConfiguration().save();
    }

    private static final String CONTROL_SAVE="<entry key=\"speps.id\">"+NEW_COUNTRY_VALUE+"</entry>";
    private void checkFileIsChanged(){
        try {
            FileInputStream fis = new FileInputStream(FILEREPO_DIR + "peps.xml");
            byte data[]=new byte[fis.available()];
            fis.read(data);
            String content=new String(data);
            assertTrue(content.contains(CONTROL_SAVE));
            fis.close();
        }catch(IOException ioe){
            fail("cannot check peps.xml");
        }
    }
}
