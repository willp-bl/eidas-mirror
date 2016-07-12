package eu.stork.peps;

import eu.stork.peps.auth.specific.IAUService;

/**
 * Class for handling spring bean definition and use it on the servlets
 */
public class SpecificIdPBean extends SpecificCommonBean {

  /**
   * Specific PEPS service.
   */
  private transient IAUService specificPeps;

  /**
   * Setter for specificPeps.
   *
   * @param specificPeps The specificPeps to set.
   */
  public void setSpecificPeps(final IAUService specificPeps) {
    this.specificPeps = specificPeps;
  }

  /**
   * Getter for specificPeps.
   *
   * @return The specificPeps value.
   */
  public IAUService getSpecificPeps() {
    return specificPeps;
  }

}
