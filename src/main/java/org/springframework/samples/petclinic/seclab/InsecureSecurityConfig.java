// src/main/java/org/springframework/samples/petclinic/seclab/InsecureSecurityConfig.java
package org.springframework.samples.petclinic.seclab;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class InsecureSecurityConfig {

    // [S4502] Disabling CSRF protection is security-sensitive (Hotspot) -- CWE-352
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}
