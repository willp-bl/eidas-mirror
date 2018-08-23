 package eu.eidas.util;
 
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

 /**
  * Node Metadata whitelist related utilities.
  */
public final class WhitelistUtil    {
    protected static final Logger LOGGER = LoggerFactory.getLogger(WhitelistUtil.class);

    public static Collection<String> metadataWhitelist(String in){
    	List<String> result = new ArrayList<>();
    	if (in==null){
    		return result;
    	}
    	for(String urlString:in.trim().replaceAll("\t", "").replaceAll("\n", "").toLowerCase().split(";")){
			try {
				URL url = new URL(urlString);
				result.add(urlString.trim());
			} catch (MalformedURLException e) {
				LOGGER.warn("Invalid url matadata: "+urlString+", in the list : "+in);
			}
    	}
    	return result;
    }
 }
