package eu.eidas.auth.commons;

import java.io.UnsupportedEncodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public final class EidasStringUtil {
    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory.getLogger(EidasStringUtil.class.getName());

	private EidasStringUtil() {
	}
	
	/**
	 * 
	 * @param b input byte array
	 * @return a String created from  @b bytes, encoded UTF-8
	 */
	public static String stringFromBytesArray(byte[] b){
		String result="";
		try{
			result=new String(b, Constants.UTF8_ENCODING);
		}catch(UnsupportedEncodingException uee){
            LOG.info("ERROR : encoding error", uee.getMessage());
            LOG.debug("ERROR : encoding error", uee);
		}
		return result;
	}

}
