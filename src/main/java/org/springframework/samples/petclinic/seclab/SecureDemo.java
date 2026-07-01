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

	// Hard-coded credentials -> externalize to the environment / config
	// In application.properties: db.user=${DB_USER} db.password=${DB_PASSWORD}
	@Value("${db.user}")
	private String dbUser;

	@Value("${db.password}")
	private String dbPassword;

	// [S1313] Using a hardcoded IP address is security-sensitive (Hotspot)
	private static final String SQL_HOST = "192.168.10.50";

	// Weak hash -> use a strong, salted password hash (BCrypt), not a raw digest
	import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
	private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

	public String hashPassword(String pw) {
		return encoder.encode(pw); // adaptive, salted hash
	}

	// Predictable PRNG -> use SecureRandom for any security value
	import java.security.SecureRandom;

	public long newSessionToken() {
		return new SecureRandom().nextLong();
	}

	// Weak cipher -> AES-256 in GCM mode with a random IV
	Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

	byte[] iv = new byte[12];

	new SecureRandom().nextBytes(iv);cipher.init(Cipher.ENCRYPT_MODE,aesKey,new GCMParameterSpec(128,iv));

	// XXE -> disable DOCTYPE and external entities on the factory
	DocumentBuilderFactory dbf = DocumentBuilderFactory
		.newInstance();

		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);dbf.setFeature("http://xml.org/sax/features/external-general-entities",false);dbf.setXIncludeAware(false);dbf.setExpandEntityReferences(false);

	// Insecure temp file -> create with restrictive permissions
	import java.nio.file.Files;
	File f = Files.createTempFile("petclinic", ".tmp").toFile();

	// SQL injection -> use a PreparedStatement with bound parameters
	String sql = "SELECT * FROM owners WHERE last_name = ?";

	PreparedStatement ps = conn.prepareStatement(sql);

	ps.setString(1,lastName);ps.executeQuery();

	// Command injection -> pass arguments as an array, validate the input
	if(!host.matches("[A-Za-z0-9.-]+"))throw new IllegalArgumentException();new ProcessBuilder("ping","-c","1",host).start();

}
