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
package eu.eidas.tests;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Properties;

import static org.junit.Assert.*;

/**
 * The EIDASUtil's Test Case.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date: $
 */
public final class EIDASUtilTestCase {

    /**
     * Message example.
     */
    private static final String MESSAGE_SAMPLE = "003002 - Authentication Failed";

    /**
     * Error message example.
     */
    private static final String ERROR_MESSAGE_SAMPLE = "Authentication Failed";

    /**
     * Error code example.
     */
    private static final String ERROR_CODE_SAMPLE = "003002";

    /**
     * Properties values for testing proposes.
     */
    private static final Properties CONFIGS1 = new Properties();

    /**
     * Properties values for testing proposes.
     */
    private static final Properties CONFIGS2 = new Properties();

    /**
     * The empty string value: "".
     */
    private static final String EMPTY_STRING = "";

    /**
     * The empty byte value: [].
     */
    private static final byte[] EMPTY_BYTE = new byte[]{};

    /**
     * The empty byte hash value.
     */
    private static final byte[] EMPTY_HASH_BYTE = new byte[]{-49, -125, -31,
            53, 126, -17, -72, -67, -15, 84, 40, 80, -42, 109, -128, 7, -42, 32, -28,
            5, 11, 87, 21, -36, -125, -12, -87, 33, -45, 108, -23, -50, 71, -48, -47,
            60, 93, -123, -14, -80, -1, -125, 24, -46, -121, 126, -20, 47, 99, -71, 49,
            -67, 71, 65, 122, -127, -91, 56, 50, 122, -7, 39, -38, 62};

    /**
     * The SAML example byte[] value.
     */
    private static final byte[] SAML_BYTE_SAMPLE = new byte[]{60, 115, 97, 109,
            108, 62, 46, 46, 46, 60, 47, 115, 97, 109, 108};

    /**
     * The SAML's Base64 example value.
     */
    private static final String SAML_BASE64_SAMPLE = "PHNhbWw+Li4uPC9zYW1s";

    /**
     * The SAML's Base64 byte[] example value.
     */
    private static byte[] SAML_BASE64_BYTE_SAMPLE = new byte[]{80, 72, 78, 104,
            98, 87, 119, 43, 76, 105, 52, 117, 80, 67, 57, 122, 89, 87, 49, 115};

    /**
     * The SAML's Base64 Hash byte[] example value.
     */
    private static byte[] HASH_BYTE_SAMPLE = new byte[]{67, 38, 11, 115, 49,
            -5, 54, -85, 38, 43, -99, 96, 71, -41, 50, -96, 71, -86, 90, -97, 66, -67,
            90, 101, 30, 82, -13, 60, -106, -72, -103, -75, 19, 2, -107, 107, -6, -56,
            34, -111, -44, -57, -26, -5, 33, 78, -1, 30, 21, 74, -26, 118, -46, -12,
            -102, 12, -56, 30, -59, -104, -21, -42, -103, 82};

    /**
     * Init EIDASUtilTestCase class.
     */
    @BeforeClass
    public static void runsBeforeTheTestSuite() {

        CONFIGS1.setProperty("max.attrList.size", "20000");
        CONFIGS1.setProperty("attrList.code", "202005");
        CONFIGS1.setProperty("attrList.message", "invalid.attrList.parameter");

        CONFIGS1.setProperty("max.qaaLevel.size", "1");
        CONFIGS1.setProperty("max.spUrl.size", "inv");
        CONFIGS1.setProperty("validation.active", "true");
        CONFIGS1.setProperty("hashDigest.className",
                "org.bouncycastle.crypto.digests.SHA512Digest");
        CONFIGS1.setProperty("invalidAgeDateValue.code", "35");
        CONFIGS1.setProperty("invalidAttributeValue.code", "34");
        CONFIGS1.setProperty("invalidAttributeValue.message",
                "Unexpected or invalid content was encountered within a "
                        + "<saml:Attribute> or <saml:AttributeValue> element.");
    }
    @Before
    public void initialize(){
        EIDASUtil.setConfigs(CONFIGS1);
    }

    /**
     * Tests the {@link EIDASUtil#createInstance(Properties)} method for the given
     * properties object.
     */
    @Test
    public void testCreateInstance() {
        Assert.assertNotNull(EIDASUtil.createInstance(null));
        Assert.assertNotNull(EIDASUtil.createInstance(CONFIGS2));
    }

    /**
     * Tests the {@link EIDASUtil#getConfigs()}.
     */
    @Test
    public void testGetConfigs() {
        EIDASUtil.setConfigs(null);
        final EIDASUtil eidasUtils = EIDASUtil.createInstance(CONFIGS1);
        Assert.assertEquals(eidasUtils.getConfigs(), CONFIGS1);
    }

    /**
     * Tests the {@link EIDASUtil#getConfigs()}.
     */
    @Test
    public void testGetConfigsDifferent() {
        final EIDASUtil eidasUtils = EIDASUtil.createInstance(CONFIGS1);
        Assert.assertNotSame(eidasUtils.getConfigs(), CONFIGS2);
    }

    /**
     * Tests the {@link EIDASUtil#getConfig(String)} method for the given existing
     * config.
     */
    @Test
    public void testGetConfigExists() {
        Assert.assertEquals(EIDASUtil.getConfig("hashDigest.className"), "org.bouncycastle.crypto.digests.SHA512Digest");
    }

    /**
     * Tests the {@link EIDASUtil#getConfig(String)} method for the given not
     * existing config.
     */
    @Test
    public void testGetConfigNoExists() {
        Assert.assertNull(EIDASUtil.getConfig("doesnt.exists"));
    }

    /**
     * Tests the {@link EIDASUtil#getConfig(String)} method for the given null
     * value.
     */
    @Test(expected = NullPointerException.class)
    public void testGetConfigNull() {
        Assert.assertNull(EIDASUtil.getConfig(null));
    }

    /**
     * Tests the {@link EIDASUtil#isValidParameter(String, String)} method for the
     * given param values.
     */
    @Test
    public void testIsValidParameterExists() {
        Assert.assertTrue(EIDASUtil.isValidParameter("qaaLevel", "1"));
    }

    /**
     * Tests the {@link EIDASUtil#isValidParameter(String, String)} method for the
     * given param values.
     */
    @Test
    public void testIsValidParameterExistsGreat() {
        Assert.assertFalse(EIDASUtil.isValidParameter("qaaLevel", "12"));
    }

    /**
     * Tests the {@link EIDASUtil#isValidParameter(String, String)} method for the
     * given param values.
     */
    @Test
    public void testIsValidParameterExistsIvalidConf() {
        Assert.assertFalse(EIDASUtil.isValidParameter("spUrl", "https://sp:8080/SP/"));
    }

    /**
     * Tests the {@link EIDASUtil#isValidParameter(String, String)} method for the
     * given param values.
     */
    @Test
    public void testIsValidParameterNotExists() {
        Assert.assertFalse(EIDASUtil.isValidParameter("doesntexists","https://sp:8080/SP/"));
    }

    /**
     * Tests the {@link EIDASUtil#isValidParameter(String, String)} method for the
     * given param values.
     */
    @Test
    public void testIsValidParameterNullParamName() {
        Assert.assertFalse(EIDASUtil.isValidParameter(null, "https://sp:8080/SP/"));
    }

    /**
     * Tests the {@link EIDASUtil#isValidParameter(String, String)} method for the
     * given param values.
     */
    @Test
    public void testIsValidParameterNullParamValue() {
        Assert.assertFalse(EIDASUtil.isValidParameter("spUrl", null));
    }

    /**
     * Tests the {@link EIDASUtil#validateParameter(String, String, Object)} method
     * for the given object values.
     */
    @Test
    public void testValidateParameterValid() {
        final IPersonalAttributeList persAttrList = new PersonalAttributeList();
        persAttrList.populate("isAgeOver:true:[15,]:Available;");
        EIDASUtil.validateParameter("ServiceProviderAction",
                EIDASParameters.ATTRIBUTE_LIST.toString(), persAttrList);
    }

    /**
     * Tests the {@link EIDASUtil#validateParameter(String, String, Object)} method
     * for the given string values.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testValidateParameterNull() {
        EIDASUtil.validateParameter("ServiceProviderAction",
                EIDASParameters.ATTRIBUTE_LIST.toString(), null);
    }

    /**
     * Tests the {@link EIDASUtil#validateParameter(String, String, String)} method
     * for the given string values.
     * <p/>
     * The tested class just invokes
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * so further tests will be later.
     */
    @Test
    public void testValidateParameter() {
        EIDASUtil.validateParameter("ServiceProviderAction",
                EIDASParameters.ATTRIBUTE_LIST.toString(),
                "isAgeOver:true:[15,]:Available;");
    }

    /**
     * Tests the
     * {@link EIDASUtil#validateParameter(String, String, String, EIDASErrors)}
     * method for the given string value and {@link EIDASErrors} enum.
     * <p/>
     * The tested class just invokes
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * so further tests will be later.
     */
    @Test
    public void testValidateParameterEIDASErrors() {
        EIDASUtil.validateParameter("CountrySelectorAction",
                EIDASParameters.ATTRIBUTE_LIST.toString(),
                "isAgeOver:true:[15,]:Available;",
                EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_ATTR);
    }

    /**
     * Tests the
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * method for the given string values.
     */
    @Test
    public void testValidateParameterValidParams() {
        EIDASUtil.validateParameter("ServiceProviderAction", "qaaLevel", "1",
                "qaaLevel.code", "qaaLevel.message");
    }

    /**
     * Tests the
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * method for the given string values.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testValidateParameterInvalidParamValue() {
        EIDASUtil.validateParameter("ServiceProviderAction", "qaaLevel", "10",
                "qaaLevel.code", "qaaLevel.message");
    }

    /**
     * Tests the
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * method for the given string values.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testValidateParameterInvalidParamName() {
        EIDASUtil.validateParameter("ServiceProviderAction", "doesnt.exists", "1",
                "qaaLevel.code", "qaaLevel.message");
    }

    /**
     * Tests the
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * method for the given string values.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testValidateParameterNullParamName() {
        EIDASUtil.validateParameter("ServiceProviderAction", null, "1",
                "qaaLevel.code", "qaaLevel.message");
    }

    /**
     * Tests the
     * {@link EIDASUtil#validateParameter(String, String, String, String, String)}
     * method for the given string values.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testValidateParameterNullParamValue() {
        EIDASUtil.validateParameter("ServiceProviderAction", "qaaLevel", null,
                "qaaLevel.code", "qaaLevel.message");
    }

    /**
     * Tests the {@link EIDASUtil#encodeSAMLToken(byte[])} method for the given
     * string value.
     */
    @Test
    public void testEncodeSAMLToken() {
        assertEquals(EIDASUtil.encodeSAMLToken(SAML_BYTE_SAMPLE), SAML_BASE64_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#encodeSAMLToken(byte[])} method for the given
     * null.
     */
    @Test(expected = NullPointerException.class)
    public void testEncodeSAMLTokenNull() {
        assertNotSame(EIDASUtil.encodeSAMLToken(null), SAML_BASE64_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#encodeSAMLToken(byte[])} method for the given
     * empty byte[] value.
     */
    @Test
    public void testEncodeSAMLTokenEmpty() {
        assertEquals(EIDASUtil.encodeSAMLToken(EMPTY_BYTE), EMPTY_STRING);
    }

    /**
     * Tests the {@link EIDASUtil#decodeSAMLToken(byte[])} method for the given
     * byte[] value.
     */
    @Test
    public void testDecodeSAMLToken() {
        assertArrayEquals(EIDASUtil.decodeSAMLToken(SAML_BASE64_SAMPLE),
                SAML_BYTE_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#decodeSAMLToken(byte[])} method for the given
     * null value.
     */
    @Test(expected = NullPointerException.class)
    public void testDecodeSAMLTokenNull() {
        assertNotSame(EIDASUtil.decodeSAMLToken(null), SAML_BYTE_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#decodeSAMLToken(byte[])} method for the given
     * empty string value.
     */
    @Test(expected = org.bouncycastle.util.encoders.DecoderException.class)
    public void testDecodeSAMLTokenEmpty() {
        assertEquals(EIDASUtil.decodeSAMLToken(EMPTY_STRING), EMPTY_BYTE);
    }

    /**
     * Tests the {@link EIDASUtil#hashPersonalToken(byte[])} method for the given
     * byte[] value.
     */
    @Test
    public void testHashPersonalToken() {
        assertArrayEquals(EIDASUtil.hashPersonalToken(SAML_BASE64_BYTE_SAMPLE),
                HASH_BYTE_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#hashPersonalToken(byte[])} method for the given
     * null value.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testHashPersonalTokenNull() {
        assertNull(EIDASUtil.hashPersonalToken(null));
    }

    /**
     * Tests the {@link EIDASUtil#hashPersonalToken(byte[])} method for the given
     * empty value.
     */
    @Test
    public void testHashPersonalTokenEmpty() {
        assertArrayEquals(EIDASUtil.hashPersonalToken(EMPTY_BYTE), EMPTY_HASH_BYTE);
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorCode(String)} method for the given
     * correct message.
     */
    @Test
    public void testGetEidasErrorCodeExists() {
        assertEquals(EIDASUtil.getEidasErrorCode(MESSAGE_SAMPLE), ERROR_CODE_SAMPLE);
    }

    @Test
    public void testGetEidasErrorCodeMultiple() {
        assertNotSame(EIDASUtil.getEidasErrorCode(MESSAGE_SAMPLE+" - TEST"), ERROR_CODE_SAMPLE);
        assertEquals(EIDASUtil.getEidasErrorCode(ERROR_MESSAGE_SAMPLE + EIDASValues.ERROR_MESSAGE_SEP.toString() + ERROR_MESSAGE_SAMPLE), null);
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorCode(String)} method for the given
     * invalid message.
     */
    @Test
    public void testGetEidasErrorCodeNoExists() {
        assertNull(EIDASUtil.getEidasErrorCode(ERROR_MESSAGE_SAMPLE));
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorCode(String)} method for the given
     * empty message.
     */
    @Test
    public void testGetEidasErrorCodeEmpty() {
        assertNull(EIDASUtil.getEidasErrorCode(EMPTY_STRING));
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorCode(String)} method for the given
     * null message.
     */
    @Test
    public void testGetEidasErrorCodeNull() {
        assertNull(EIDASUtil.getEidasErrorCode(null));
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorCode(String)} method for the given
     * invalid message.
     */
    @Test
    public void testGetEidasErrorCodeWithSepFake() {
        assertNull(EIDASUtil.getEidasErrorCode("-"));
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorCode(String)} method for the given
     * invalid message.
     */
    @Test
    public void testGetEidasErrorCodeWithSepAndCodeFake() {
        assertNull(EIDASUtil.getEidasErrorCode("000001 -"));
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorMessage(String)} method for the
     * given correct message.
     */
    @Test
    public void testGetEidasErrorMessageExists() {
        assertEquals(EIDASUtil.getEidasErrorMessage(MESSAGE_SAMPLE),
                ERROR_MESSAGE_SAMPLE);
    }

    @Test
    public void testGetEidasErrorMessageMultiple() {
        assertNotSame(EIDASUtil.getEidasErrorMessage(MESSAGE_SAMPLE + " - TEST"), ERROR_MESSAGE_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorMessage(String)} method for the
     * given invalid message.
     */
    @Test
    public void testGetEidasErrorMessageNoExists() {
        assertEquals(EIDASUtil.getEidasErrorMessage(ERROR_MESSAGE_SAMPLE),
                ERROR_MESSAGE_SAMPLE);
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorMessage(String)} method for the
     * given empty message.
     */
    @Test
    public void testGetEidasErrorMessageEmpty() {
        assertEquals(EIDASUtil.getEidasErrorMessage(EMPTY_STRING),
                EMPTY_STRING);
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorMessage(String)} method for the
     * given null message.
     */
    @Test
    public void testGetEidasErrorMessageNull() {
        assertNull(EIDASUtil.getEidasErrorMessage(null));
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorMessage(String)} method for the
     * given invalid message.
     */
    @Test
    public void testGetEidasErrorMessageWithSepFake() {
        assertEquals(EIDASUtil.getEidasErrorMessage("-"), "-");
    }

    /**
     * Tests the {@link EIDASUtil#getEidasErrorMessage(String)} method for the
     * given invalid message.
     */
    @Test
    public void testGetEidasErrorMessageWithSepAndCodeFake() {
        assertEquals(EIDASUtil.getEidasErrorMessage("000001 -"), "000001 -");
    }

    @Test
    public void testIsValidParameterWithoutValidation() {
        Properties configLocal = new Properties();
        configLocal.setProperty("validation.active", "false");
        EIDASUtil.setConfigs(configLocal);
        Assert.assertTrue(EIDASUtil.isValidParameter("qaaLevel", "1"));
    }

}
