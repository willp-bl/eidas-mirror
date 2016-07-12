package eu.stork.samlengineconfig;

import eu.stork.samlengineconfig.impl.marshaller.EngineInstanceUnmarshallerImpl;

import eu.stork.samlengineconfig.SamlEngineConfiguration;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;

public class TestEngineInstanceUnmarshaller {
    String TEST_REAL="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<instances>\n" +
            "\n" +
            "\t<!-- ******************** CPEPS ******************** -->\n" +
            "\t<!-- Configuration name -->\n" +
            "\t<instance name=\"CPEPS\">\n" +
            "\t\t<!-- Configurations parameters StorkSamlEngine -->\n" +
            "\t\t<configuration name=\"SamlEngineConf\">\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"StorkSamlEngine_CPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "\t\t<!-- Settings module signature -->\n" +
            "\t\t<configuration name=\"SignatureConf\">\n" +
            "\t\t\t<!-- Specific signature module -->\n" +
            "\t\t\t<parameter name=\"class\"\n" +
            "\t\t\t\tvalue=\"eu.stork.peps.auth.engine.core.impl.SignSW\" />\n" +
            "\t\t\t<!-- Settings specific module -->\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"SignModule_CPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "        <!-- Settings module encryption -->\n" +
            "        <configuration name=\"EncryptionConf\">\n" +
            "            <!-- Specific signature module -->\n" +
            "            <parameter name=\"class\"\n" +
            "                       value=\"eu.stork.peps.auth.engine.core.impl.EncryptionSW\" />\n" +
            "            <!-- Settings specific module\n" +
            "                 responseTo/FromPointAlias & requestTo/FromPointAlias parameters will be added -->\n" +
            "            <parameter name=\"fileConfiguration\" value=\"EncryptModule_CPEPS-CB.xml\" />\n" +
            "            <!-- Settings for activation of the encryption. If file not found then no encryption applies-->\n" +
            "            <parameter name=\"fileActivationConfiguration\"\n" +
            "                       value=\"c:\\PGM\\projects\\configStork\\encryptionConf.xml\" />\n" +
            "        </configuration>\n" +
            "\t</instance>" +
            "</instances>";

    private static final String TEST_IBM_JVM="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<instances>\n" +
            "\n" +
            "\t<!-- ******************** CPEPS ******************** -->\n" +
            "\t<!-- Configuration name -->\n" +
            "\t<instance name=\"CPEPS\">\n" +
            "\t\t<!-- Configurations parameters StorkSamlEngine -->\n" +
            "\t\t<configuration name=\"SamlEngineConf\">\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"StorkSamlEngine_CPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "\t\t<!-- Settings module signature -->\n" +
            "\t\t<configuration name=\"SignatureConf\">\n" +
            "\t\t\t<!-- Specific signature module -->\n" +
            "\t\t\t<parameter name=\"class\"\n" +
            "\t\t\t\tvalue=\"eu.stork.peps.auth.engine.core.impl.SignSW\" />\n" +
            "\t\t\t<!-- Settings specific module -->\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"SignModule_CPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "        <!-- Settings module encryption -->\n" +
            "        <configuration name=\"EncryptionConf\">\n" +
            "            <!-- Specific signature module -->\n" +
            "            <parameter name=\"class\"\n" +
            "                       value=\"eu.stork.peps.auth.engine.core.impl.EncryptionSW\" />\n" +
            "            <!-- Settings specific module\n" +
            "                 responseTo/FromPointAlias & requestTo/FromPointAlias parameters will be added -->\n" +
            "            <parameter name=\"fileConfiguration\" value=\"EncryptModule_CPEPS-CB.xml\" />\n" +
            "            <!-- Settings for activation of the encryption. If file not found then no encryption applies-->\n" +
            "            <parameter name=\"fileActivationConfiguration\"\n" +
            "                       value=\"c:\\PGM\\projects\\configStork\\encryptionConf.xml\" />\n" +
            "        </configuration>\n" +
            "\t</instance>\n" +
            "\n" +
            "\t<!-- ******************** SP-SPEPS ******************** -->\n" +
            "\n" +
            "\t<instance name=\"SP-SPEPS\">\n" +
            "\t\t<configuration name=\"SamlEngineConf\">\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"StorkSamlEngine_SP-SPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "\t\t<configuration name=\"SignatureConf\">\n" +
            "\t\t\t<parameter name=\"class\"\n" +
            "\t\t\t\tvalue=\"eu.stork.peps.auth.engine.core.impl.SignSW\" />\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"SignModule_SP-SPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "        <configuration name=\"EncryptionConf\">\n" +
            "            <!-- Specific signature module -->\n" +
            "            <parameter name=\"class\"\n" +
            "                       value=\"eu.stork.peps.auth.engine.core.impl.EncryptionSW\" />\n" +
            "            <!-- Settings specific module\n" +
            "                 responseTo/FromPointAlias & requestTo/FromPointAlias parameters will be added -->\n" +
            "            <parameter name=\"fileConfiguration\" value=\"EncryptModule_SP-SPEPS-CB.xml\" />\n" +
            "            <!-- Settings for activation of the encryption. If file not found then no encryption applies-->\n" +
            "            <parameter name=\"fileActivationConfiguration\"\n" +
            "                       value=\"c:\\PGM\\projects\\configStork\\encryptionConf.xml\" />\n" +
            "        </configuration>\n" +
            "\t</instance>\n" +
            "\n" +
            "\n" +
            "\t<!-- ******************** SPEPS-CPEPS ******************** -->\n" +
            "\n" +
            "\t<instance name=\"SPEPS-CPEPS\">\n" +
            "\t\t<configuration name=\"SamlEngineConf\">\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"StorkSamlEngine_SPEPS-CPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "\t\t<configuration name=\"SignatureConf\">\n" +
            "\t\t\t<parameter name=\"class\"\n" +
            "\t\t\t\tvalue=\"eu.stork.peps.auth.engine.core.impl.SignSW\" />\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"SignModule_SPEPS-CPEPS.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "        <configuration name=\"EncryptionConf\">\n" +
            "            <!-- Specific signature module -->\n" +
            "            <parameter name=\"class\"\n" +
            "                       value=\"eu.stork.peps.auth.engine.core.impl.EncryptionSW\" />\n" +
            "            <!-- Settings specific module\n" +
            "                 responseTo/FromPointAlias & requestTo/FromPointAlias parameters will be added -->\n" +
            "            <parameter name=\"fileConfiguration\" value=\"EncryptModule_SPEPS-CPEPS-CB.xml\" />\n" +
            "            <!-- Settings for activation of the encryption. If file not found then no encryption applies-->\n" +
            "            <parameter name=\"fileActivationConfiguration\"\n" +
            "                       value=\"c:\\PGM\\projects\\configStork\\encryptionConf.xml\" />\n" +
            "        </configuration>\n" +
            "\t</instance>\n" +
            "\n" +
            "\t<!-- ******************** Specific ******************** -->\n" +
            "\t<!-- Configuration name -->\n" +
            "\t<instance name=\"Specific\">\n" +
            "\t\t<!-- Configurations parameters StorkSamlEngine -->\n" +
            "\t\t<configuration name=\"SamlEngineConf\">\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"StorkSamlEngine_Specific.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "\t\t<!-- Settings module signature -->\n" +
            "\t\t<configuration name=\"SignatureConf\">\n" +
            "\t\t\t<!-- Specific signature module -->\n" +
            "\t\t\t<parameter name=\"class\"\n" +
            "\t\t\t\tvalue=\"eu.stork.peps.auth.engine.core.impl.SignSW\" />\n" +
            "\t\t\t<!-- Settings specific module -->\n" +
            "\t\t\t<parameter name=\"fileConfiguration\" value=\"SignModule_Specific.xml\" />\n" +
            "\t\t</configuration>\n" +
            "\n" +
            "        <configuration name=\"EncryptionConf\">\n" +
            "            <!-- Specific signature module -->\n" +
            "            <parameter name=\"class\"\n" +
            "                       value=\"eu.stork.peps.auth.engine.core.impl.EncryptionSW\" />\n" +
            "            <!-- Settings specific module\n" +
            "                 responseTo/FromPointAlias & requestTo/FromPointAlias parameters will be added -->\n" +
            "            <parameter name=\"fileConfiguration\" value=\"EncryptModule_Specific-CB.xml\" />\n" +
            "            <!-- Settings for activation of the encryption. If file not found then no encryption applies-->\n" +
            "            <parameter name=\"fileActivationConfiguration\"\n" +
            "                       value=\"c:\\PGM\\projects\\configStork\\encryptionConf_specific.xml\" />\n" +
            "        </configuration>\n" +
            "\t</instance>\n" +
            "\n" +
            "</instances>";
    private static final String TEST_SIMPLE="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
            "<instances name=\"oo\">\n" +
            "    <instance name=\"engineinstance1\" >\n" +
            "        <configuration name=\"name11\">\n" +
            "            <parameter name=\"sp-name111\" value=\"sp-value111\"></parameter>\n" +
            "        </configuration>\n" +
            "    </instance>\n" +
            "    <instance name=\"engineinstance2\" >\n" +
            "        <configuration name=\"name21\">\n" +
            "            <parameter name=\"sp-name211\" value=\"sp-value211\"></parameter>\n" +
            "        </configuration>\n" +
            "    </instance>\n" +
            "</instances>";

    @Test
    public void testDeserialize(){
        EngineInstanceUnmarshallerImpl eiui=new EngineInstanceUnmarshallerImpl();
        SamlEngineConfiguration ec = eiui.readEngineInstanceFromString(TEST_SIMPLE);
        assertNotNull(ec);
        assertEquals(ec.getInstances().size(), 2);
        assertEquals(ec.getInstances().get(0).getConfigurations().size(), 1);
        assertNotNull(ec.getInstances().get(0).getConfigurations().get(0).getName());
        assertNotNull(ec.getInstances().get(0).getConfigurations().get(0).getParameters());
        assertFalse(ec.getInstances().get(0).getConfigurations().get(0).getParameters().isEmpty());
    }
    @Test
    public void testDeserializeIBM_JVMtest(){
        EngineInstanceUnmarshallerImpl eiui=new EngineInstanceUnmarshallerImpl();
        SamlEngineConfiguration ec = eiui.readEngineInstanceFromString(TEST_IBM_JVM);
        assertNotNull(ec);
        assertEquals(ec.getInstances().size(), 4);
    }
}
