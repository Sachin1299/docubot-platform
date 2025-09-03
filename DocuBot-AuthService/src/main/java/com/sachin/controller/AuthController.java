package com.sachin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.sachin.dto.AuthenticationRequest;
import com.sachin.entity.User;
import com.sachin.service.AuthenticationService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController  // ✅ Fixed annotation
@RequestMapping("/api/auth")  // ✅ Use @RequestMapping instead
public class AuthController {

    @Autowired
    private AuthenticationService authservice;

    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@RequestBody User user) {
        try {
            String token = authservice.register(user).getToken();
            return ResponseEntity.ok(token);
        } catch(Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthenticationRequest request,
                                        HttpServletResponse response){
        // If service throws, it’s mapped by @RestControllerAdvice
        String token = authservice.login(request).getToken();

        ResponseCookie cookie = ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(24 * 60 * 60)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(token);
    }

    
    @GetMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response){
    	try {
    	ResponseCookie cookie = ResponseCookie.from("jwt",null)
    			.httpOnly(true)
    			.secure(true)
    			.sameSite("None")
    			.path("/")
    			.maxAge(0)
    			.build();
    	
    	response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    	return ResponseEntity.ok("Logout Successfull");
    	}
    	catch(Exception e) {
    		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
    	}
    }
    
    
//    @GetMapping("/check")
//    public ResponseEntity<String> loginCheck(){
////    	Cookie[] cookies = request.getCookies();
////    	System.out.println("Cookie: " + cookies[0].getValue());
////    	if (cookies != null) {
////    	    for (Cookie c : cookies) {
////    	        System.out.println("Cookie: " + c.getName() + "=" + c.getValue());
////    	    }
////    	} else {
////    	    System.out.println("No cookies");
////    	}
//    	try {
//    		return ResponseEntity.status(HttpStatus.OK).build();
//    	}catch(Exception e) {
//    	return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//    	}
//    }
    
    @GetMapping("/check")
    public ResponseEntity<String> loginCheck(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.ok("Authenticated as: " + authentication.getName());
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not authenticated");
    }

}
