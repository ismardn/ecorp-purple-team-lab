package fr.christophetd.log4shell.vulnerableapp;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

@RestController
public class MainController {

    private static final Logger logger = LogManager.getLogger(MainController.class);

    public static class LoginRequest {
        private String username;
        private String password;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    @PostMapping("/api/login")
    public String login(@RequestBody LoginRequest credentials) {
        
        String username = credentials.getUsername();
        String password = credentials.getPassword();

        // Vulnérabilité Log4Shell
        logger.info("Login attempt: " + username);

        String adServer = "ldap://10.0.20.5:389";
        String domain = "@ecorp.local";

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, adServer);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, username + domain);
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            new InitialDirContext(env).close();
            logger.info("Authentication status: SUCCESS");
            return "SUCCESS";
        } catch (Exception e) {
            logger.error("Authentication status: FAIL");
            return "FAIL";
        }
    }
}
