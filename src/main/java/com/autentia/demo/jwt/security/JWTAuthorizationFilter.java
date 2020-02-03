package com.autentia.demo.jwt.security;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static com.autentia.demo.jwt.security.Constants.*;

/*
 verifica la cabecera en busca de un token, se verifica el token y
 se extrae la información del mismo para establecer la identidad del usuario
 dentro del contexto de seguridad de la aplicación
 No se requieren accesos adicionales a BD ya que al estar firmado digitalmente si
 hay alguna alteración en el token se corrompe.
 */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(HEADER_AUTHORIZACION_KEY);

        if(header == null || !header.startsWith(TOKEN_BEARER_PREFIX)){
            chain.doFilter(request,response);
            return;
        }
        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_AUTHORIZACION_KEY);
        if(token !=null)
        {
            //Se procesa el token y se recupera el usuario
            String user = Jwts.parser()
                        .setSigningKey(SUPER_SECRET_KEY)
                        .parseClaimsJws(token.replace(TOKEN_BEARER_PREFIX, ""))
                        .getBody()
                        .getSubject();
            if(user !=null)
                return new UsernamePasswordAuthenticationToken(user,null, new ArrayList<>());
            else
                return null;
        }
        else
            return null;
    }
}
