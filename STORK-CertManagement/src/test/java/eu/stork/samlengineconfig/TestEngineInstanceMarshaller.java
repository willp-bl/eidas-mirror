package eu.stork.samlengineconfig;

import eu.stork.samlengineconfig.impl.SamlEngineConfigurationImpl;
import eu.stork.samlengineconfig.impl.EngineInstanceImpl;
import eu.stork.samlengineconfig.impl.InstanceConfigurationImpl;
import eu.stork.samlengineconfig.impl.marshaller.EngineInstanceMarshallerImpl;

import eu.stork.samlengineconfig.SamlEngineConfiguration;
import eu.stork.samlengineconfig.EngineInstance;
import eu.stork.samlengineconfig.StringParameter;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

public class TestEngineInstanceMarshaller {
    @Test
    public void testSerialize(){
        EngineInstanceMarshallerImpl eimi=new EngineInstanceMarshallerImpl();
        SamlEngineConfiguration config=new SamlEngineConfigurationImpl();
        EngineInstance instance=new EngineInstanceImpl();
        StringParameter sp=new StringParameter();
        sp.setName("sp-name");
        sp.setValue("sp-value");
        InstanceConfigurationImpl ic=new InstanceConfigurationImpl("name",null);
        ic.getParameters().add(sp);
        instance.addConfiguration(ic);
        instance.setName("engineinstance");
        config.addInstance(instance);
        String s=eimi.serializeEngineInstance(config);
        assertNotNull(s);
        assertNotNull(s);
    }
}
