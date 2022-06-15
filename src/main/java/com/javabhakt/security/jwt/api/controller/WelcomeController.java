package com.javabhakt.security.jwt.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.javabhakt.security.jwt.api.entity.AuthRequest;
import com.javabhakt.security.jwt.api.entity.User;
import com.javabhakt.security.jwt.api.service.GroupUserDetails;
import com.javabhakt.security.jwt.api.util.JwtUtil;

@RestController
public class WelcomeController {

	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@GetMapping("/")
	public String welcome () {
		return "Welcome to javabhakt classes...";
	}
	
	@PostMapping("/authenticate")
	public String generateToken (@RequestBody AuthRequest authRequest) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
		} catch (Exception ex) {
			throw new Exception ("Invalid Username/password");
		}
		
		GroupUserDetails groupUserDetails = new GroupUserDetails(authRequest.getUsername(), authRequest.getPassword());
		groupUserDetails.setUsername(authRequest.getUsername());
		return jwtUtil.generateToken(groupUserDetails);
		
	}
	
}
