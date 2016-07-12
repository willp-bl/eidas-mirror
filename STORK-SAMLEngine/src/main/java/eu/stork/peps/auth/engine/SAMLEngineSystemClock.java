package eu.stork.peps.auth.engine;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SAMLEngineClock implementation that corresponds with the system clock.
 */
public class SAMLEngineSystemClock implements SAMLEngineClock {
    private static final Logger LOG = LoggerFactory.getLogger(SAMLEngineSystemClock.class.getName());

    public DateTime getCurrentTime() {
        LOG.trace("getCurrentTime");
        return new DateTime(DateTimeZone.UTC);
    }
}