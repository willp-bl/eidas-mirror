package eu.stork.config;

import eu.stork.config.impl.FileConfigurationRepository;
import eu.stork.config.impl.FilePEPSConfiguration;
import eu.stork.impl.file.FileService;
import eu.stork.samlengineconfig.*;
import eu.stork.samlengineconfig.impl.EngineInstanceImpl;
import eu.stork.samlengineconfig.impl.InstanceConfigurationImpl;
import eu.stork.samlengineconfig.impl.SamlEngineConfigurationImpl;
import eu.stork.samlengineconfig.impl.marshaller.EngineInstanceMarshallerImpl;
import eu.stork.samlengineconfig.impl.marshaller.EngineInstanceUnmarshallerImpl;
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

import java.io.*;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * reads a PEPS configuration
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="/testcontext.xml")
@FixMethodOrder(MethodSorters.JVM)
public class TestPepsConfig {
    private static final String FILEREPO_DIR="src/test/resources/config/";
    private static final String FILEREPO_DIR_INCORRECT_COUNTRYNUMBER="src/test/resources/configIncorrectCountryNumber/";
    private static final String FILEREPO_DIR_INVALID_COUNTRYNUMBER="src/test/resources/configInvalidCountryNumber/";
    @Autowired
    private PEPSMasterConfiguration pepsMasterConfiguration = null;

    @Before
    public void setUp(){
        assertNotNull(pepsMasterConfiguration);
    }
    @Test
    public void testReadPepsXMLConfig(){
        ((FileConfigurationRepository)(pepsMasterConfiguration.getRepository())).getFileService().setRepositoryDir(FILEREPO_DIR);
        pepsMasterConfiguration.getPepsConfiguration().load();
        Properties pepsProps = pepsMasterConfiguration.getPepsConfiguration().getPepsProperties();
        assertNotNull(pepsProps);
        assertFalse(pepsProps.isEmpty());
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getPepsParameters());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getPepsParameters().isEmpty());
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().isEmpty());
        assertEquals(2, pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().size());
    }
    @Test
    public void testReadPepsXMLConfigIncorrectCpepsNumber(){
        ((FileConfigurationRepository)(pepsMasterConfiguration.getRepository())).getFileService().setRepositoryDir(FILEREPO_DIR_INCORRECT_COUNTRYNUMBER);
        pepsMasterConfiguration.getPepsConfiguration().load();
        Properties pepsProps = pepsMasterConfiguration.getPepsConfiguration().getPepsProperties();
        assertNotNull(pepsProps);
        assertFalse(pepsProps.isEmpty());
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getPepsParameters());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getPepsParameters().isEmpty());
        assertNotNull(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries());
        assertFalse(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().isEmpty());
        assertEquals(2, pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().size());
        assertEquals("8", pepsProps.getProperty("cpeps.number"));
    }
    @Test
    public void testReadPepsXMLConfigInvalidCpepsNumber(){
        ((FileConfigurationRepository)(pepsMasterConfiguration.getRepository())).getFileService().setRepositoryDir(FILEREPO_DIR_INVALID_COUNTRYNUMBER);
        pepsMasterConfiguration.getPepsConfiguration().load();
        Properties pepsProps = pepsMasterConfiguration.getPepsConfiguration().getPepsProperties();
        assertTrue(pepsMasterConfiguration.getPepsConfiguration().getPepsCountries().isEmpty());
        assertEquals("a", pepsProps.getProperty("cpeps.number"));
    }


}
