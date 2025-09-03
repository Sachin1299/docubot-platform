package com.docservice.security;


import com.docservice.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    @Autowired
    private JwtService jwtUtil;



    // The ObjectMapper is used to write a JSON response
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {
    	
        try {   
            final String jwtToken = jwtUtil.getJwtFromCookies(request);
            System.out.println("Cookies : "+request.getCookies());
            System.out.println("JwtToken: "+jwtToken);
            final String userEmail = jwtUtil.extractUsername(jwtToken);

            // If token is valid, configure Spring Security to manually set authentication
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
               

                // Note: The original isTokenValid re-parsed the token.
                // Assuming your JwtService confirms the token hasn't expired and matches the user.
            
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userEmail,
                                    null
                            );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            
            // Continue the filter chain
            filterChain.doFilter(request, response);

        } catch (JwtException ex) {
            // This block is executed when the token is invalid (e.g., tampered, expired)
            // We directly create and send the 401 Unauthorized response

            // Set the response status to 401 Unauthorized
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            // Create a clear error message body
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("message", "Invalid or expired JWT token.");
            errorDetails.put("error", ex.getMessage());
            
            // Write the error message to the response body
            response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
            
            // By not calling filterChain.doFilter(), we stop the request processing here.
            // The 'return' is implicit as this is the end of the method execution path.
        }
        catch (UsernameNotFoundException ex) {
        	response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            // Create a clear error message body
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("message", "User doesn't exit.");
            errorDetails.put("error", ex.getMessage());
            
            // Write the error message to the response body
            response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
            
            // By not calling filterChain.doFilter(), we stop the request processing here.
            // The 'return' is implicit as this is the end of the method execution path.
        }
        catch (Exception ex) {
            // This block is executed when the token is invalid (e.g., tampered, expired)
            // We directly create and send the 401 Unauthorized response

            // Set the response status to 401 Unauthorized
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            // Create a clear error message body
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("message", "Invalid or expired JWT token.");
            errorDetails.put("error", ex.getMessage());
            
            // Write the error message to the response body
            response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
            
            // By not calling filterChain.doFilter(), we stop the request processing here.
            // The 'return' is implicit as this is the end of the method execution path.
        }
        
    }
    
    

}