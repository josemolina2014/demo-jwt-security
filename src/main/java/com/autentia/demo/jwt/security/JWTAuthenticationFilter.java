package com.autentia.demo.jwt.security;

import com.autentia.demo.jwt.usuario.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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

import static com.autentia.demo.jwt.security.Constants.*;

/**
 * Haciendo uso de las clases proporcionadas por Spring Security, extendemos su comportamiento para reflejar nuestras necesidades.
 * Se verifica que las credencias proporcionadas son válidas y se genera el JWT.
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            Usuario credenciales = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                                credenciales.getUsername(),
                                credenciales.getPassword(),
                                new ArrayList<>()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        String token = Jwts.builder()
                .setIssuedAt(new Date()).setIssuer(ISSUER_INFO)
                .setSubject(((User)auth.getPrincipal()).getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SUPER_SECRET_KEY).compact();
        response.addHeader(HEADER_AUTHORIZACION_KEY, TOKEN_BEARER_PREFIX+" "+token);
    }
    /*
    No hay obligación de devolver el token en la cabecera ni con una clave concreta pero se recomienda seguir los estándares utilizados en la actualidad (RFC 2616, RFC 6750).
    Lo habitual es devolverlo en la cabecera HTTP utilizando la clave “Authorization” e indicando que el valor es un token “Bearer “ + token
     */
}
