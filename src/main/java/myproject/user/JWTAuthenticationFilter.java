package myproject.domain.user;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import static myproject.domain.user.SecurityUtils.EXPIRATION_TIME;
import static myproject.domain.user.SecurityUtils.TOKEN_PREFIX;
import static myproject.domain.user.SecurityUtils.HEADER_STRING;
import static myproject.domain.user.SecurityUtils.SECRET;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger log = Logger.getLogger(JWTAuthenticationFilter.class);
    private AuthenticationManager authenticationManager;
    private ApplicationUserRepository applicationUserRepository;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, ApplicationUserRepository
            applicationUserRepository) {
        this.authenticationManager = authenticationManager;
        this.applicationUserRepository = applicationUserRepository;
        setFilterProcessesUrl("/api/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws
            AuthenticationException {
        try {
            ApplicationUser creds = new ObjectMapper().readValue(req.getInputStream(), ApplicationUser.class);

            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(),
                    creds.getPassword(), new ArrayList<>()));
        } catch (IOException e) {
            log.error("Error occurred during authentication: " + e.getMessage());
            e.printStackTrace();
        } catch (AuthenticationException e) {
            log.error("Error occurred during authentication: " + e.getMessage());
            e.printStackTrace();
        } finally {
            return null;
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
String token = Jwts.builder()
                .setSubject(((User) auth.getPrincipal()).getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET.getBytes())
                .compact();

String username = ((User) auth.getPrincipal()).getUsername();

res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + SecurityUtils.generateToken(username) );

        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
    }
}
