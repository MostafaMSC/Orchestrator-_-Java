package iq.twokeyok.orchestrator.config;

import java.security.Security;

import jakarta.annotation.PostConstruct;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

/**
 * Registers Bouncy Castle once at start-up.
 *
 * <p>The ADSS Client SDK needs it whenever the orchestrator hashes documents
 * itself ({@code local-hash: true}) or upgrades a signature to PAdES-LT/LTV, and
 * the SDK samples register it the same way.</p>
 */
@Configuration
public class CryptoProviderConfig {

    private static final Logger log = LoggerFactory.getLogger(CryptoProviderConfig.class);

    @PostConstruct
    void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            log.info("Registered the Bouncy Castle security provider");
        }
    }
}
