package eu.eidas.engine.test.simple;

import org.joda.time.DateTime;

import eu.eidas.auth.engine.SamlEngineClock;

/**
 * A SamlEngineClock test implementation that can set its time relative to the system clock.
 */

public class SamlEngineTestClock implements SamlEngineClock {
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
