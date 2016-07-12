package eu.eidas.node.auth.util.tests.logback_integrity;

import eu.eidas.node.logging.logback_integrity.HashFileChecker;

import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * @author vanegdi
 */
public class HashFileCheckerTest {
    @Test
    public void testValidEntry() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #1# [+7ojMjYzoLMYIl8lzT7mgrI2SMSs4KLUWwcVBMquKlM=]\n").getBytes());
        assertTrue(HashFileChecker.check(is, "SHA-256"));
    } @Test
    public void testLongerValidFile() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #1# [+7ojMjYzoLMYIl8lzT7mgrI2SMSs4KLUWwcVBMquKlM=]\n" +
        "2015-03-26; 09:55:38.855 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #2# [EXCwHb/cO2R0XahMUctJVu2JMc5kKhEBK36xACWl85g=]\n" +
        "2015-03-26; 09:55:38.857 [main] WARN  eu.test.appli  - - -Session is missing or invalid #3# [1l137/ppIbm0MhasxVYD0nwAY+ZKIZ1AnQMAA4kJFd0=]\n" +
        "2015-03-26; 09:55:38.861 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #4# [7Q5VvImVlLOUfEGd2qRHUVQMs4Iv9Zce1BkM3w1q2Uo=]\n" +
        "2015-03-26; 09:55:38.864 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #5# [KG73aXnqYmxJg1/8QYjVglwg4p/WWGLzXDxG9mGLIfA=]\n").getBytes());
        assertTrue(HashFileChecker.check(is, "SHA-256"));
    }
    /**
     * The number of log entry is not consistent.
     */
    @Test()
    public void testInvalidText() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #2# [+7ojMjYzoLMYIl8lzT7mgrI2SMSs4KLUWwcVBMquKlM=]\n").getBytes());
        assertFalse(HashFileChecker.check(is, "SHA-256"));
    }
    /**
     * The hash is not consistent
     */
    @Test
    public void testInvalidHash() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #1# [+7ojMjYzM=]\n").getBytes());
        assertFalse(HashFileChecker.check(is, "SHA-256"));
    }

    @Test(expected=IllegalStateException.class)
    public void testMissingText() throws Exception{
        InputStream is = new ByteArrayInputStream(("[+7ojMjYzM=]\n").getBytes());
        HashFileChecker.check(is, "SHA-256");
    }
    @Test(expected=IllegalStateException.class)
    public void testMissingHash() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #1#\n").getBytes());
        HashFileChecker.check(is, "SHA-256");
    }
    @Test(expected=IllegalStateException.class)
    public void testMissingTrailingHash() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #1# []\n").getBytes());
        HashFileChecker.check(is, "SHA-256");
    }
    /**
     * Takes the longerValidFile without the line #3#.
     */
    @Test
    public void testMissingEntry() throws Exception{
        InputStream is = new ByteArrayInputStream(("2015-03-26; 09:55:38.848 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #1# [+7ojMjYzoLMYIl8lzT7mgrI2SMSs4KLUWwcVBMquKlM=]\n" +
                "2015-03-26; 09:55:38.855 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #2# [EXCwHb/cO2R0XahMUctJVu2JMc5kKhEBK36xACWl85g=]\n" +
                "2015-03-26; 09:55:38.861 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #4# [7Q5VvImVlLOUfEGd2qRHUVQMs4Iv9Zce1BkM3w1q2Uo=]\n" +
                "2015-03-26; 09:55:38.864 [main] INFO  eu.test.appli  - - -== SESSION : Test.getAuthenticationRequest Called, size is 0 #5# [KG73aXnqYmxJg1/8QYjVglwg4p/WWGLzXDxG9mGLIfA=]\n").getBytes());
        assertFalse(HashFileChecker.check(is, "SHA-256"));
    }
}