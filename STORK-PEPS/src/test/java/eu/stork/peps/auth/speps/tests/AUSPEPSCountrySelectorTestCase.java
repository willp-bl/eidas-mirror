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
package eu.stork.peps.auth.speps.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;

import eu.stork.peps.auth.commons.Country;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.speps.AUSPEPSCountrySelector;
import eu.stork.peps.auth.speps.AUSPEPSUtil;
import eu.stork.peps.auth.speps.ISPEPSSAMLService;
import eu.stork.peps.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link AUSPEPSCountrySelector}.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSPEPSCountrySelectorTestCase {

    private Properties getTestConfigWithOnePeps() {
        Properties testConfig = new Properties();
        testConfig.setProperty(PEPSParameters.PEPS_NUMBER.toString(), TestingConstants.ONE_CONS.toString());
        testConfig.setProperty(PEPSValues.CPEPS_PREFIX.index(1), TestingConstants.LOCAL_CONS.toString());
        testConfig.setProperty(PEPSValues.CPEPS_PREFIX.name(1), TestingConstants.LOCAL_CONS.toString());
        return testConfig;
    }

    private AUSPEPSUtil getPepsUtilWithOnePeps() {
        Properties testConfig = getTestConfigWithOnePeps();

        AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        auspepsUtil.setConfigs(testConfig);

        auspepsUtil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auspepsUtil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());

        return auspepsUtil;
    }

    private Map<String, String> getTestParameters(){
        Map<String, String> testParameters = new HashMap<String, String>();

        testParameters.put(PEPSParameters.SP_QAALEVEL.toString(), TestingConstants.QAALEVEL_CONS.toString());
        testParameters.put(PEPSParameters.SP_ID.toString(), TestingConstants.SPID_CONS.toString());
        testParameters.put(PEPSParameters.ATTRIBUTE_LIST.toString(), "Idade:false:[15,]:Available;");

        return testParameters;
    }

    private Properties getTestPepsUtilConfig(){
        Properties testPepsUtilConfig = new Properties();

        testPepsUtilConfig.put(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorCode(), "0000001");
        testPepsUtilConfig.put(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorMessage(), "invalid.spQAAId.parameter");

        testPepsUtilConfig.put(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorCode(), "000006");
        testPepsUtilConfig.put(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID.errorMessage(), "attr.access.deny");

        testPepsUtilConfig.put(PEPSParameters.SP_ID.toString(), "Idade");

        return testPepsUtilConfig;
    }

    /**
     * Test method for {@link AUSPEPSCountrySelector#createCountrySelector()} .
     * Must Succeed.
     */
    @Test
    public void testCreateCountrySelector() {
        final AUSPEPSCountrySelector auspepsCountrySelector = new AUSPEPSCountrySelector();

        auspepsCountrySelector.setSpepsUtil(getPepsUtilWithOnePeps());

        final Country country = new Country(TestingConstants.LOCAL_CONS.toString(), TestingConstants.LOCAL_CONS.toString());
        List<Country> countries = new ArrayList<Country>(1);
        countries.add(country);

        assertEquals(countries.size(), auspepsCountrySelector.createCountrySelector().size());
        assertSame(countries.get(0).getCountryId(), auspepsCountrySelector.createCountrySelector().get(0).getCountryId());
        assertSame(countries.get(0).getCountryName(), auspepsCountrySelector.createCountrySelector().get(0).getCountryName());
    }
    /*
     * Test method for {@link AUSPEPSCountrySelector#createCountrySelector()} .
     * Must Succeed.
     */
    @Test
    public void testCreateCountrySelectorTwoSizedList() {
        final AUSPEPSCountrySelector auspepsCountrySelector = new AUSPEPSCountrySelector();
        Properties testConfig = new Properties();
        testConfig.setProperty(PEPSParameters.PEPS_NUMBER.toString(), TestingConstants.TWO_CONS.toString());

        AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        auspepsUtil.setConfigs(testConfig);

        auspepsCountrySelector.setSpepsUtil(auspepsUtil);

        auspepsCountrySelector.createCountrySelector();
    }

    /**
     * Test method for
     * {@link AUSPEPSCountrySelector#checkCountrySelectorRequest(Map, ISPEPSSAMLService)}
     * . Testing invalid SP. Must throw a {@link InvalidParameterPEPSException}.
     */
    @Test(expected = InvalidParameterPEPSException.class)
    public void testCheckCountrySelectorRequestSPInvalid() {
        PEPSUtil.createInstance(getTestPepsUtilConfig());
        final AUSPEPSCountrySelector auspepsCountrySelector = new AUSPEPSCountrySelector();

        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);
        auspepsCountrySelector.setSpepsUtil(getPepsUtilWithOnePeps());
        auspepsCountrySelector.checkCountrySelectorRequest(getTestParameters(), spepsSAMLService);
    }

    /**
     * Test method for
     * {@link AUSPEPSCountrySelector#checkCountrySelectorRequest(Map, ISPEPSSAMLService)}
     * . Testing not allowed attributes. Must throw a
     * {@link InvalidParameterPEPSException}.
     */
    @Test(expected = InvalidParameterPEPSException.class)
    public void testCheckCountrySelectorRequestSPNotAllowed() {
        PEPSUtil.createInstance(getTestPepsUtilConfig());

        final AUSPEPSCountrySelector auspepscountrySel = new AUSPEPSCountrySelector();
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        AUSPEPSUtil auspepsUtil = getPepsUtilWithOnePeps();

        auspepsUtil.getConfigs().put(TestingConstants.SPID_CONS.getQaaLevel(), TestingConstants.QAALEVEL_CONS.toString());

        auspepscountrySel.setSpepsUtil(auspepsUtil);
        auspepscountrySel.checkCountrySelectorRequest(getTestParameters(), spepsSAMLService);
    }

    /**
     * Test method for
     * {@link AUSPEPSCountrySelector#checkCountrySelectorRequest(Map, ISPEPSSAMLService)}
     * . Must Succeed.
     */
    @Test
    public void testCheckCountrySelectorRequestEmptyProviderName() {
        Map<String, String> testParameters = getTestParameters();
        testParameters.put(PEPSParameters.PROVIDER_NAME_VALUE.toString(), null);

        final AUSPEPSCountrySelector auspepscountrySel = new AUSPEPSCountrySelector();
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        AUSPEPSUtil auspepsUtil = getPepsUtilWithOnePeps();

        auspepsUtil.getConfigs().put(TestingConstants.SPID_CONS.getQaaLevel(), TestingConstants.QAALEVEL_CONS.toString());
        auspepsUtil.getConfigs().put(PEPSValues.DEFAULT.toString(), TestingConstants.ALL_CONS.toString());

        PEPSUtil.setConfigs(getTestPepsUtilConfig());
        auspepscountrySel.setSpepsUtil(auspepsUtil);

        final STORKAuthnRequest authData = auspepscountrySel.checkCountrySelectorRequest(testParameters, spepsSAMLService);
        assertEquals(TestingConstants.SPID_CONS.toString(), authData.getProviderName());
    }

    /**
     * Test method for
     * {@link AUSPEPSCountrySelector#checkCountrySelectorRequest(Map, ISPEPSSAMLService)}
     * . Must Succeed.
     */
    @Test
    public void testCheckCountrySelectorRequest() {
        final AUSPEPSCountrySelector auspepsCountrySelector = new AUSPEPSCountrySelector();
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        Map<String, String> testParameters = getTestParameters();
        testParameters.put(PEPSParameters.PROVIDER_NAME_VALUE.toString(), TestingConstants.PROVIDERNAME_CONS.toString());

        AUSPEPSUtil auspepsUtil = getPepsUtilWithOnePeps();

        auspepsUtil.getConfigs().put(TestingConstants.SPID_CONS.getQaaLevel(), TestingConstants.QAALEVEL_CONS.toString());
        auspepsUtil.getConfigs().put(PEPSValues.DEFAULT.toString(), TestingConstants.ALL_CONS.toString());

        PEPSUtil.setConfigs(getTestPepsUtilConfig());

        auspepsCountrySelector.setSpepsUtil(auspepsUtil);

        final STORKAuthnRequest authData = auspepsCountrySelector.checkCountrySelectorRequest(testParameters, spepsSAMLService);
        assertEquals(TestingConstants.PROVIDERNAME_CONS.toString(), authData.getProviderName());
    }
}
