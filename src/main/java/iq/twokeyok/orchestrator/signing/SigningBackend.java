package iq.twokeyok.orchestrator.signing;

/**
 * The signing engine behind the orchestrator.
 *
 * <p>The only implementation today is
 * {@link iq.twokeyok.orchestrator.signing.adss.AdssSigningBackend}, which drives
 * the ADSS Client SDK. Keeping it behind an interface leaves room for a CSC REST
 * backend that talks to RAS over {@code /csc/v1/*} without touching the web
 * layer.</p>
 */
public interface SigningBackend {

    /** Creates a PAdES signature over every document of the job. */
    SignJob.SignResult signPades(SignJob job);
}
