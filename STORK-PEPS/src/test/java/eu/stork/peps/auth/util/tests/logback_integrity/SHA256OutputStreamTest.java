package eu.stork.peps.auth.util.tests.logback_integrity;

import eu.stork.peps.logging.logback_integrity.HashAndCounterGenerator;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Single test cases for HASH256 output log.
 * @author vanegdi
 */
public class SHA256OutputStreamTest {
    /**
     * Test a single log generation
     */
    @Test
    public void testSingleLog() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HashAndCounterGenerator hashAndCounterGenerator = new HashAndCounterGenerator(byteArrayOutputStream, true, "SHA-256");
        hashAndCounterGenerator.write("TestA\n".getBytes());
        hashAndCounterGenerator.flush();
        String result = new String(byteArrayOutputStream.toByteArray());
        assertEquals("TestA #1# [kQYTvzcedONYovA2OkEpDihUOl1PyapPioklXt04RgE=]\n",result);
    }

    /**
     * Test a single log generation
     */
    @Test
    public void testSingleLogWithoutcounter() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HashAndCounterGenerator hashAndCounterGenerator = new HashAndCounterGenerator(byteArrayOutputStream, false, "SHA-256");
        hashAndCounterGenerator.write("TestA\n".getBytes());
        hashAndCounterGenerator.flush();
        String result = new String(byteArrayOutputStream.toByteArray());
        assertEquals("TestA [qsKaWzzzT1lv5mgcj7ySG9tN9/4S9w0/qf7meMhJ7i4=]\n",result);
    }

    /**
     * Test a single log with coherent logging line
     */
    @Test
    public void testSingleLogComplex() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HashAndCounterGenerator hashAndCounterGenerator = new HashAndCounterGenerator(byteArrayOutputStream, true, "SHA-256");
        hashAndCounterGenerator.write("2015-03-26; 09:55:38.848 [main] INFO  eu.stork.peps.auth.speps.AUSPEPS  - - -== SESSION : AUSPEPS.getAuthenticationRequest Called, size is 0\n".getBytes());
        hashAndCounterGenerator.flush();
        String result = new String(byteArrayOutputStream.toByteArray());
        assertEquals("2015-03-26; 09:55:38.848 [main] INFO  eu.stork.peps.auth.speps.AUSPEPS  - - -== SESSION : AUSPEPS.getAuthenticationRequest Called, size is 0 #1# [zddAiurv157ma1imuTAQ/l8OgA/X+hSNsS+ESqOz6Zw=]\n",result);
    }

    /**
     * Test a double line log generation with CR-LF instead of single LF
     */
    @Test
    public void testDoubleLogwithCR() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HashAndCounterGenerator hashAndCounterGenerator = new HashAndCounterGenerator(byteArrayOutputStream, true, "SHA-256");
        hashAndCounterGenerator.write("TestA\r\nTestB\r\n".getBytes());
        hashAndCounterGenerator.flush();
        String result = new String(byteArrayOutputStream.toByteArray());
        assertEquals(
                "TestA #1# [kQYTvzcedONYovA2OkEpDihUOl1PyapPioklXt04RgE=]\nTestB #2# [oGtSUycjJdFkXuOrSRV/5Hy2kE1US8SCLBMKjRv9mw8=]\n",
                result);
    }

    /**
     * Test a double line log generation with 2 different line content
     */
    @Test
    public void testDoubleLogComplex() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HashAndCounterGenerator hashAndCounterGenerator = new HashAndCounterGenerator(byteArrayOutputStream, true, "SHA-256");
        hashAndCounterGenerator.write(("2015-03-26; 09:55:38.848 [main] INFO  eu.stork.peps.auth.speps.AUSPEPS  - - -== SESSION : AUSPEPS.getAuthenticationRequest Called, size is 0\n" +
                "2015-03-26; 09:55:38.855 [main] INFO  eu.stork.peps.auth.speps.AUSPEPS  - - -== SESSION : AUSPEPS.getAuthenticationRequest Called, size is 0\n").getBytes());
        hashAndCounterGenerator.flush();
        String result = new String(byteArrayOutputStream.toByteArray());
        assertEquals("2015-03-26; 09:55:38.848 [main] INFO  eu.stork.peps.auth.speps.AUSPEPS  - - -== SESSION : AUSPEPS.getAuthenticationRequest Called, size is 0 #1# [zddAiurv157ma1imuTAQ/l8OgA/X+hSNsS+ESqOz6Zw=]\n" +
                        "2015-03-26; 09:55:38.855 [main] INFO  eu.stork.peps.auth.speps.AUSPEPS  - - -== SESSION : AUSPEPS.getAuthenticationRequest Called, size is 0 #2# [4xvKn/cq10GRwnVc0CWjZ6sp+c+jlTxNtdgQhP1BMnY=]\n",
                result);
    }


    @Test
    public void testMultipleLog() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HashAndCounterGenerator hashAndCounterGenerator = new HashAndCounterGenerator(byteArrayOutputStream, true, "SHA-256");
        hashAndCounterGenerator.write("TestA\nTestB\nTestC\n".getBytes());
        hashAndCounterGenerator.flush();
        String result = new String(byteArrayOutputStream.toByteArray());
        assertEquals(
                "TestA #1# [kQYTvzcedONYovA2OkEpDihUOl1PyapPioklXt04RgE=]\nTestB #2# [oGtSUycjJdFkXuOrSRV/5Hy2kE1US8SCLBMKjRv9mw8=]\nTestC #3# [+PUueHVsyR46ZU6CbNmMfClsVSwD+0Jjw9z++hqWzao=]\n",
                result);
    }
}
