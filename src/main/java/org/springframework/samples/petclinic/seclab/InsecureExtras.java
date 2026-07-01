// src/main/java/org/springframework/samples/petclinic/seclab/InsecureExtras.java
package org.springframework.samples.petclinic.seclab;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class InsecureExtras {

	// [S4830] Disabling certificate validation (Vulnerability) -- CWE-295
	public X509TrustManager trustEverything() {
		return new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] chain, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return new X509Certificate[0];
			}
		};
	}

}