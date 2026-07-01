// src/main/java/org/springframework/samples/petclinic/seclab/InsecureDemo.java
package org.springframework.samples.petclinic.seclab;

import java.security.MessageDigest;
import java.util.Random;
import java.io.File;
import java.sql.Connection;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;

public class InsecureDemo {

	// [S2068] Hard-coded credentials are security-sensitive (Hotspot)
	private static final String DB_USER = "admin";

	private static final String DB_PASSWORD = "P@ssw0rd123!";

	// [S1313] Using a hardcoded IP address is security-sensitive (Hotspot)
	private static final String SQL_HOST = "192.168.10.50";

	// [S4790] Weak hashing algorithm (Hotspot) -- CWE-328
	public byte[] hashPassword(String pw) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		return md.digest(pw.getBytes());
	}

	// [S2245] Predictable pseudorandom generator used for a token (Hotspot)
	public long newSessionToken() {
		Random random = new Random();
		return random.nextLong();
	}

	// [S5542 / S5547] Weak cipher: DES in ECB mode, no padding (Hotspot)
	public byte[] encrypt(byte[] data, byte[] key) throws Exception {
		SecretKeySpec sk = new SecretKeySpec(key, "DES");
		Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, sk);
		return cipher.doFinal(data);
	}

	// [S2755] XML parser vulnerable to XXE (Vulnerability) -- CWE-611
	public DocumentBuilderFactory parserFactory() {
		// No external-entity protections set -> XXE
		return DocumentBuilderFactory.newInstance();
	}

	// [S5443] Insecure temp file in a shared/world-readable directory (Hotspot)
	public File scratchFile() throws Exception {
		return File.createTempFile("petclinic", ".tmp", new File("/tmp"));
	}

	// [TAINT - not confirmed in Community Build] SQL injection via concatenation
	public void findOwner(Connection conn, String lastName) throws Exception {
		Statement st = conn.createStatement();
		String sql = "SELECT * FROM owners WHERE last_name = '" + lastName + "'";
		st.executeQuery(sql);
	}

	// [TAINT - not confirmed in Community Build] OS command injection
	public void ping(String host) throws Exception {
		Runtime.getRuntime().exec("ping -c 1 " + host);
	}

}
