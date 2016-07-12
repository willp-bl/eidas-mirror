/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations 
 * under the License.
 */
package eu.eidas.node.auth.connector.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;

import eu.eidas.auth.commons.Country;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.node.auth.connector.AUCONNECTORCountrySelector;
import eu.eidas.node.auth.connector.AUCONNECTORUtil;
import eu.eidas.node.auth.connector.ICONNECTORSAMLService;
import eu.eidas.node.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link AUCONNECTORCountrySelector}.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCONNECTORCountrySelectorTestCase {

    private Properties getTestConfigWithOneNode() {
        Properties testConfig = new Properties();
        testConfig.setProperty(EIDASParameters.EIDAS_NUMBER.toString(), TestingConstants.ONE_CONS.toString());
        testConfig.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1), TestingConstants.LOCAL_CONS.toString());
        testConfig.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1), TestingConstants.LOCAL_CONS.toString());
        return testConfig;
    }

    private AUCONNECTORUtil getNodeUtilWithOneNode() {
        Properties testConfig = getTestConfigWithOneNode();

        AUCONNECTORUtil auconnectorUtil = new AUCONNECTORUtil();
        auconnectorUtil.setConfigs(testConfig);

        auconnectorUtil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auconnectorUtil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());

        return auconnectorUtil;
    }

    private Map<String, String> getTestParameters(){
        Map<String, String> testParameters = new HashMap<String, String>();

        testParameters.put(EIDASParameters.SP_QAALEVEL.toString(), TestingConstants.QAALEVEL_CONS.toString());
        testParameters.put(EIDASParameters.SP_ID.toString(), TestingConstants.SPID_CONS.toString());
        testParameters.put(EIDASParameters.ATTRIBUTE_LIST.toString(), "Idade:false:[15,]:Available;");

        return testParameters;
    }

    private Properties getTestNodeUtilConfig(){
        Properties testUtilConfig = new Properties();

        testUtilConfig.put(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorCode(), "0000001");
        testUtilConfig.put(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorMessage(), "invalid.spQAAId.parameter");

        testUtilConfig.put(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorCode(), "000006");
        testUtilConfig.put(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorMessage(), "attr.access.deny");

        testUtilConfig.put(EIDASParameters.SP_ID.toString(), "Idade");

        return testUtilConfig;
    }

    /**
     * Test method for {@link AUCONNECTORCountrySelector#createCountrySelector()} .
     * Must Succeed.
     */
    @Test
    public void testCreateCountrySelector() {
        final AUCONNECTORCountrySelector auconnectorCountrySelector = new AUCONNECTORCountrySelector();

        auconnectorCountrySelector.setConnectorUtil(getNodeUtilWithOneNode());

        final Country country = new Country(TestingConstants.LOCAL_CONS.toString(), TestingConstants.LOCAL_CONS.toString());
        List<Country> countries = new ArrayList<Country>(1);
        countries.add(country);

        assertEquals(countries.size(), auconnectorCountrySelector.createCountrySelector().size());
        assertSame(countries.get(0).getCountryId(), auconnectorCountrySelector.createCountrySelector().get(0).getCountryId());
        assertSame(countries.get(0).getCountryName(), auconnectorCountrySelector.createCountrySelector().get(0).getCountryName());
    }
    /*
     * Test method for {@link AUConnectorCountrySelector#createCountrySelector()} .
     * Must Succeed.
     */
    @Test
    public void testCreateCountrySelectorTwoSizedList() {
        final AUCONNECTORCountrySelector auconnectorCountrySelector = new AUCONNECTORCountrySelector();
        Properties testConfig = new Properties();
        testConfig.setProperty(EIDASParameters.EIDAS_NUMBER.toString(), TestingConstants.TWO_CONS.toString());

        AUCONNECTORUtil auconnectorUtil = new AUCONNECTORUtil();
        auconnectorUtil.setConfigs(testConfig);

        auconnectorCountrySelector.setConnectorUtil(auconnectorUtil);

        auconnectorCountrySelector.createCountrySelector();
    }

    /**
     * Test method for
     * {@link AUCONNECTORCountrySelector#checkCountrySelectorRequest(Map, ICONNECTORSAMLService)}
     * . Testing invalid SP. Must throw a {@link InvalidParameterEIDASException}.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testCheckCountrySelectorRequestSPInvalid() {
        EIDASUtil.createInstance(getTestNodeUtilConfig());
        final AUCONNECTORCountrySelector auconnectorCountrySelector = new AUCONNECTORCountrySelector();

        final ICONNECTORSAMLService connectorSAMLService = mock(ICONNECTORSAMLService.class);
        auconnectorCountrySelector.setConnectorUtil(getNodeUtilWithOneNode());
        auconnectorCountrySelector.checkCountrySelectorRequest(getTestParameters(), connectorSAMLService);
    }

    /**
     * Test method for
     * {@link AUCONNECTORCountrySelector#checkCountrySelectorRequest(Map, ICONNECTORSAMLService)}
     * . Testing not allowed attributes. Must throw a
     * {@link InvalidParameterEIDASException}.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testCheckCountrySelectorRequestSPNotAllowed() {
        EIDASUtil.createInstance(getTestNodeUtilConfig());

        final AUCONNECTORCountrySelector auconnectorcountrySel = new AUCONNECTORCountrySelector();
        final ICONNECTORSAMLService connectorSAMLService = mock(ICONNECTORSAMLService.class);

        AUCONNECTORUtil auconnectorUtil = getNodeUtilWithOneNode();

        auconnectorUtil.getConfigs().put(TestingConstants.SPID_CONS.getQaaLevel(), TestingConstants.QAALEVEL_CONS.toString());

        auconnectorcountrySel.setConnectorUtil(auconnectorUtil);
        auconnectorcountrySel.checkCountrySelectorRequest(getTestParameters(), connectorSAMLService);
    }

    /**
     * Test method for
     * {@link AUCONNECTORCountrySelector#checkCountrySelectorRequest(Map, ICONNECTORSAMLService)}
     * . Must Succeed.
     */
    @Test
    public void testCheckCountrySelectorRequestEmptyProviderName() {
        Map<String, String> testParameters = getTestParameters();
        testParameters.put(EIDASParameters.PROVIDER_NAME_VALUE.toString(), null);

        final AUCONNECTORCountrySelector auconnectorcountrySel = new AUCONNECTORCountrySelector();
        final ICONNECTORSAMLService connectorSAMLService = mock(ICONNECTORSAMLService.class);

        AUCONNECTORUtil auconnectorUtil = getNodeUtilWithOneNode();

        auconnectorUtil.getConfigs().put(TestingConstants.SPID_CONS.getQaaLevel(), TestingConstants.QAALEVEL_CONS.toString());
        auconnectorUtil.getConfigs().put(EIDASValues.DEFAULT.toString(), TestingConstants.ALL_CONS.toString());

        EIDASUtil.setConfigs(getTestNodeUtilConfig());
        auconnectorcountrySel.setConnectorUtil(auconnectorUtil);

        final EIDASAuthnRequest authData = auconnectorcountrySel.checkCountrySelectorRequest(testParameters, connectorSAMLService);
        assertEquals(TestingConstants.SPID_CONS.toString(), authData.getProviderName());
    }

    /**
     * Test method for
     * {@link AUCONNECTORCountrySelector#checkCountrySelectorRequest(Map, ICONNECTORSAMLService)}
     * . Must Succeed.
     */
    @Test
    public void testCheckCountrySelectorRequest() {
        final AUCONNECTORCountrySelector auconnectorCountrySelector = new AUCONNECTORCountrySelector();
        final ICONNECTORSAMLService connectorSAMLService = mock(ICONNECTORSAMLService.class);

        Map<String, String> testParameters = getTestParameters();
        testParameters.put(EIDASParameters.PROVIDER_NAME_VALUE.toString(), TestingConstants.PROVIDERNAME_CONS.toString());

        AUCONNECTORUtil auconnectorUtil = getNodeUtilWithOneNode();

        auconnectorUtil.getConfigs().put(TestingConstants.SPID_CONS.getQaaLevel(), TestingConstants.QAALEVEL_CONS.toString());
        auconnectorUtil.getConfigs().put(EIDASValues.DEFAULT.toString(), TestingConstants.ALL_CONS.toString());

        EIDASUtil.setConfigs(getTestNodeUtilConfig());

        auconnectorCountrySelector.setConnectorUtil(auconnectorUtil);

        final EIDASAuthnRequest authData = auconnectorCountrySelector.checkCountrySelectorRequest(testParameters, connectorSAMLService);
        assertEquals(TestingConstants.PROVIDERNAME_CONS.toString(), authData.getProviderName());
    }
}
