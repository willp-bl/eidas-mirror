package eu.stork.config;

import eu.stork.config.impl.CategoryListImpl;
import eu.stork.config.impl.PEPSMetaconfigHolderImpl;
import eu.stork.config.impl.PEPSMetaconfigListImpl;
import eu.stork.config.impl.PEPSMetaconfigProviderImpl;
import eu.stork.config.impl.marshaller.PEPSMetadataUnmarshallerImpl;
import eu.stork.config.peps.PEPSMetaconfigProvider;
import eu.stork.config.peps.PEPSParameterMeta;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="/testcontext.xml")
@FixMethodOrder(MethodSorters.JVM)
public class TestPepsMetadata {
    String TEST_LABEL="SP QAA level";
    String TEST_CONTENT="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
    "<PEPSMetadata>\n" +
    "    <categories>\n" +
    "        <category name=\"cpeps\">CPEPS parameters</category>\n" +
    "        <category name=\"speps\">SPEPS parameters</category>\n" +
    "    </categories>\n" +
    "    <parameters>\n" +
    "        <parameter name=\"DEMO-SP.qaalevel\">\n" +
    "                <category>speps</category>\n" +
    "            <info>information about this parameter</info>\n" +
    "            <label>"+TEST_LABEL+"</label>\n" +
    "            <default>3</default>\n" +
    "            <type>boolean</type>\n" +
    "        </parameter>\n" +
    "        <parameter name=\"sp.default.parameters\">\n" +
    "                <category>speps</category>\n" +
    "            <info>information about this parameter</info>\n" +
    "            <label>sp.default.parameters</label>\n" +
    "            <default>all</default>\n" +
    "        </parameter>\n" +
    "        <parameter name=\"speps.spInstitution\">\n" +
    "                <category>cpeps</category>\n" +
    "                <category>speps</category>\n" +
    "            <info>speps.spInstitution information about this parameter</info>\n" +
    "            <label>speps.spInstitution</label>\n" +
    "            <default>DEMO-SPEPS</default>\n" +
    "        </parameter>\n" +
    "    </parameters>\n" +
    "</PEPSMetadata>";
    final static String TEST_CATEGORY="parameter.category.label.administer.cpeps";


    @Test
    public void testDeserialize(){
        PEPSMetadataUnmarshallerImpl eiui=new PEPSMetadataUnmarshallerImpl();
        PEPSMetaconfigHolderImpl holder = eiui.readPEPSMetadataFromString(TEST_CONTENT);
        assertNotNull(holder);
        CategoryListImpl categories = holder.getCategoryList();
        PEPSMetaconfigListImpl metadataList=holder.getPEPSMetadataList();
        assertNotNull(categories);
        assertNotNull(categories.getCategories());
        assertFalse(categories.getCategories().isEmpty());
        assertTrue(categories.getCategories().size() == 2);
        assertNotNull(metadataList);
        assertNotNull(metadataList.getPEPSParameterMetadaList());
        assertFalse(metadataList.getPEPSParameterMetadaList().isEmpty());
        assertTrue(metadataList.getPEPSParameterMetadaList().size() == 3);
        boolean checkLabel=false;
        for(PEPSParameterMeta pepsparammeta:metadataList.getPEPSParameterMetadaList()){
            if(TEST_LABEL.equals(pepsparammeta.getLabel())){
                checkLabel=true;
                break;
            }
        }
        assertTrue(checkLabel);
    }

    @Test
    public void testPEPSMetadataProvider(){
        PEPSMetaconfigProviderImpl provider = new PEPSMetaconfigProviderImpl();
        assertNotNull(provider.getCategories());
        assertFalse(provider.getCategories().isEmpty());
        assertFalse(provider.getCategorizedParameters().isEmpty());
        assertTrue(provider.getCategoryParameter(TEST_CATEGORY).size() == 10);
    }

    @Autowired
    private PEPSMetaconfigProvider metadataProvider = null;

    @Test
    public void testPEPSMetadataProviderByString(){
        assertNotNull(metadataProvider);
        assertNotNull(metadataProvider.getCategories());
        assertFalse(metadataProvider.getCategories().isEmpty());
        assertFalse(metadataProvider.getCategorizedParameters().isEmpty());
    }

}
