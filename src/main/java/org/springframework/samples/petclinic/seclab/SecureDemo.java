// src/main/java/org/springframework/samples/petclinic/seclab/SecureDemo.java
package org.springframework.samples.petclinic.seclab;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;

public class SecureDemo {

	// FIXED: no hard-coded secrets; read from environment at call time
	private String dbUser() {
		return System.getenv("DB_USER");
	}

	private String dbPassword() {
		return System.getenv("DB_PASSWORD");
	}

	// FIXED [S1313]: host comes from configuration, not a literal
	private String sqlHost() {
		return System.getenv("SQL_HOST");
	}

	// FIXED [S4790]: use SHA-256 instead of MD5
	public byte[] hashPassword(String pw) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(pw.getBytes("UTF-8"));
	}

	// FIXED [S2245]: SecureRandom for any security value
	public long newSessionToken() {
		return new SecureRandom().nextLong();
	}

	// FIXED [S5542/S5547]: AES-256 in GCM with a random IV
	public byte[] encrypt(byte[] data, SecretKeySpec aesKey) throws Exception {
		byte[] iv = new byte[12];
		new SecureRandom().nextBytes(iv);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
		return cipher.doFinal(data);
	}

	// FIXED [S2755]: disable DOCTYPE and external entities
	public DocumentBuilderFactory parserFactory() throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
		dbf.setXIncludeAware(false);
		dbf.setExpandEntityReferences(false);
		return dbf;
	}

	// FIXED [S5443]: temp file with default (restrictive) permissions
	public File scratchFile() throws Exception {
		return Files.createTempFile("petclinic", ".tmp").toFile();
	}

	// FIXED [CWE-89]: parameterized query, no string concatenation
	public void findOwner(Connection conn, String lastName) throws Exception {
		String sql = "SELECT * FROM owners WHERE last_name = ?";
		try (PreparedStatement ps = conn.prepareStatement(sql)) {
			ps.setString(1, lastName);
			ps.executeQuery();
		}
	}

	// FIXED [CWE-78]: argument array + input validation, no shell string
	public void ping(String host) throws Exception {
		if (!host.matches("[A-Za-z0-9.-]+")) {
			throw new IllegalArgumentException("invalid host");
		}
		new ProcessBuilder("ping", "-c", "1", host).start();
	}

}