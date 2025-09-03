package com.sachin.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.sachin.dto.AuthenticationRequest;
import com.sachin.dto.AuthenticationResponse;
import com.sachin.entity.Provider;
import com.sachin.entity.User;
import com.sachin.exception.GoogleAccountOnlyException;
import com.sachin.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	public AuthenticationResponse register(User request) {
		if (!userRepository.findByEmail(request.getEmail()).isEmpty()) {
			throw new IllegalArgumentException("Email already registered");
		}

		var user = User.builder().name(request.getName()).email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword())).build();
		System.out.println("trying to save user");
		userRepository.save(user);
		var jwtToken = jwtService.generateToken(user.getEmail());
		return new AuthenticationResponse(jwtToken);
	}

	// In AuthenticationService.login
	public AuthenticationResponse login(AuthenticationRequest request) {
	    var user = userRepository.findByEmail(request.getEmail())
	        .orElseThrow(() -> new IllegalArgumentException("Invalid email"));

	    // If you added Provider in User
	    if (user.getProvider() == Provider.GOOGLE) {
	        // Throw a typed exception you’ll map to 409, or return a special result
	        throw new GoogleAccountOnlyException("This account uses Google Sign-In. Please continue with Google.");
	    }

	    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
	        throw new IllegalArgumentException("Invalid credentials");
	    }

	    var jwtToken = jwtService.generateToken(user.getEmail());
	    return new AuthenticationResponse(jwtToken);
	}

}
