// src/main/java/org/springframework/samples/petclinic/seclab/InsecureExtras.java
package org.springframework.samples.petclinic.seclab;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;

public class SecureExtras {

	// FIXED [S4830] -- do NOT implement a trust-all X509TrustManager.
	// Use the platform's default trust managers, which validate the
	// certificate chain against the JVM's trusted CA store.
	public SSLContext secureContext() throws Exception {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

		// Passing null loads the JVM's default trust store (the CA bundle).
		tmf.init((KeyStore) null);

		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, tmf.getTrustManagers(), null);
		return ctx;
	}

}