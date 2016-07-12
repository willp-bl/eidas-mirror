package eu.stork.config;

import eu.stork.FileUtils;
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

import java.io.File;
import java.util.List;

import static org.junit.Assert.*;

/**
 * write a peps configuration, also an encryptionConf.xml file
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="/testcontext.xml")
@FixMethodOrder(MethodSorters.JVM)
public class TestFileService {
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
        FileUtils.copyFile(new File(FILEREPO_DIR_READ), new File(FILEREPO_DIR_WRITE));
        configUtil.getFileService().setRepositoryDir(FILEREPO_DIR_WRITE);
    }
    @After
    public void removeDir(){
        java.io.File samplePepsRepo=new java.io.File(FILEREPO_DIR_WRITE);
        FileSystemUtils.deleteRecursively(samplePepsRepo);
    }

    @Test
    public void testFileList(){
        List<String> fileList= configUtil.getFileService().getFileList(true);
        assertFalse(fileList.isEmpty());
        assertTrue(fileList.size()==3);
    }

    @Test
    public void testBackup(){
        List<String> fileList= configUtil.getFileService().getFileList(true);
        assertTrue(fileList.size()==3);
        configUtil.getFileService().backup();
        fileList= configUtil.getFileService().getFileList(false);
        assertTrue(fileList.size()>4);
    }

}
