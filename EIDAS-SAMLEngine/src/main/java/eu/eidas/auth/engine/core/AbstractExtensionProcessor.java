package eu.eidas.auth.engine.core;

import eu.eidas.auth.engine.EIDASSAMLEngine;
import org.apache.commons.lang.StringUtils;

public abstract class AbstractExtensionProcessor implements ExtensionProcessorI{
    public String getAttributeFullName(final EIDASSAMLEngine engine, String name){
        String attributeName = engine.getSamlCoreProperties().getProperty(namePrefix()+name);

        if(StringUtils.isBlank(attributeName)) {
            attributeName = engine.getSamlCoreProperties().getProperty(name);
        }
        return attributeName;
    }

}
