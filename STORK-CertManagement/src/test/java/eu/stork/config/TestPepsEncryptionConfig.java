package eu.stork.config;

import eu.stork.config.impl.FileConfigurationRepository;
import eu.stork.config.peps.PEPSCountry;
import eu.stork.samlengineconfig.impl.tools.StorkConfigManagerUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.FileSystemUtils;

import java.util.Properties;

import static org.junit.Assert.*;

/**
 * write a peps configuration, also an encryptionConf.xml file
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="/testcontext.xml")
@FixMethodOrder(MethodSorters.JVM)
public class TestPepsEncryptionConfig {
    private static final String FILEREPO_DIR_READ="src/test/resources/config/";
    private static final String FILEREPO_DIR_WRITE="target/test/samplepepsconfig/";
    @Autowired
    private PEPSMasterConfiguration pepsMasterConfiguration = null;
    @Autowired
    private StorkConfigManagerUtil configUtil = null;

    @Before
    public void setUp(){
        assertNotNull(pepsMasterConfiguration);
        java.io.File samplePepsRepo=new java.io.File(FILEREPO_DIR_WRITE);
        FileSystemUtils.deleteRecursively(samplePepsRepo);
        samplePepsRepo.mkdirs();
        (new java.io.File(FILEREPO_DIR_WRITE+"samlengine/")).mkdirs();
        configUtil.getFileService().setRepositoryDir(FILEREPO_DIR_READ);
    }
    @After
    public void removeDir(){
        java.io.File samplePepsRepo=new java.io.File(FILEREPO_DIR_WRITE);
        FileSystemUtils.deleteRecursively(samplePepsRepo);
    }

    @Test
    public void testWritePepsXMLConfig(){
        pepsMasterConfiguration.getPepsConfiguration().load();
        Properties pepsProps = pepsMasterConfiguration.getPepsConfiguration().getPepsProperties();
        assertNotNull(pepsProps);
        assertFalse(pepsProps.isEmpty());
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getPepsParameters());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getPepsParameters().isEmpty());
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().isEmpty());
        assertEquals(2, pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().size());
        for(int i=0;i<2;i++){
            PEPSCountry country = pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().get(i);
            country.setEncryptionTo(true);
            country.setEncryptionFrom(false);
        }
        configUtil.getFileService().setRepositoryDir(FILEREPO_DIR_WRITE);
        pepsMasterConfiguration.getPepsConfiguration().save();
    }

}
