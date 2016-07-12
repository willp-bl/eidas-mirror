package eu.eidas.engine.test.simple;

import eu.eidas.auth.engine.SAMLEngineClock;

import org.joda.time.DateTime;

/**
 * A SAMLEngineClock test implementation that can set its time relative to the system clock.
 */

public class SAMLEngineTestClock implements SAMLEngineClock {
    private long delta = 0;

    public DateTime getCurrentTime() {
        return new DateTime().plus(delta);
    }

    /**
     * Sets the delta time that this clock deviates from the system clock.
     *
     * @param deltaTime the delta time in milliseconds
     */
    public void setDelta(long deltaTime) {
        delta = deltaTime;
    }
}
