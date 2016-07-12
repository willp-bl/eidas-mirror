package eu.eidas.engine.test.simple.eidas;

import eu.eidas.auth.engine.core.eidas.EidasAttributesTypes;
import eu.eidas.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;
import org.junit.Test;

import static org.junit.Assert.*;

public class EidasExtensionProcessorTest {

    private static final String TEST_ATTRIBUTE_FULL_NAME="http://eidas.europa.eu/attributes/EidasAdditionalAttribute";
    private static final String TEST_ATTRIBUTE_INVALID="not found";
    @Test
    public void testGetDynamicAtributeType() throws Exception {
        EidasAttributesTypes eat = EidasExtensionProcessor.getDynamicAtributeType(TEST_ATTRIBUTE_FULL_NAME);
        assertNotNull(eat);
        assertEquals(eat, EidasAttributesTypes.NATURAL_PERSON_OPTIONAL);
        eat = EidasExtensionProcessor.getDynamicAtributeType(TEST_ATTRIBUTE_INVALID);
        assertNull(eat);
        eat = EIDASAttributes.getAttributeType(TEST_ATTRIBUTE_FULL_NAME);
        assertNotNull(eat);
        assertEquals(eat, EidasAttributesTypes.NATURAL_PERSON_OPTIONAL);
    }
}