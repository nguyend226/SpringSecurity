package com.ets.sprinsecurity.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ets.sprinsecurity.dto.Role;
import com.ets.sprinsecurity.dto.User;
import com.ets.sprinsecurity.enums.ERole;
import com.ets.sprinsecurity.payload.request.LoginRequest;
import com.ets.sprinsecurity.payload.request.SignupRequest;
import com.ets.sprinsecurity.payload.response.JwtResponse;
import com.ets.sprinsecurity.payload.response.MessageResponse;
import com.ets.sprinsecurity.repo.RoleRepository;
import com.ets.sprinsecurity.repo.UserRepository;
import com.ets.sprinsecurity.security.jwt.JwtUtils;
import com.ets.sprinsecurity.security.service.UserDetailsImpl;

@CrossOrigin("*")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	JwtUtils jwtUtils;
	@Autowired
	PasswordEncoder encoder;
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		// custom response
		// spring security
		// ResponseEntity.status(200).body(object)
		// Validating the credentials
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(), loginRequest.getPassword()));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		String jwt = jwtUtils.generateJwtToken(authentication);
		UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();
		
		List<String> roles = userDetailsImpl.getAuthorities()
				.stream()
				.map(item->item.getAuthority())
				.collect(Collectors.toList());
		// jwtUtils will help us to get the token
		return ResponseEntity.ok(new JwtResponse(jwt, userDetailsImpl.getId(),
				userDetailsImpl.getUsername(), userDetailsImpl.getEmail(), roles));
	}
	
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){
		
		//username should not be existing one
		if(userRepository.existsByUsername(signupRequest.getUsername())){
			return ResponseEntity.badRequest().body(new MessageResponse("error : username is already taken"));
		}
		
		if(userRepository.existsByEmail(signupRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("error: email is already taken"));
		}
		
		//create the user
		// tp register new user ====> we need details in user entity
		//user entity based on user entity
		
		User user = new User(signupRequest.getUsername(),signupRequest.getEmail(), 
				encoder.encode(signupRequest.getPassword()));
		Set<String> strRoles = signupRequest.getRole();
		Set<Role> roles = new HashSet<>();
		
		if(strRoles == null) {
			//do we need to apply default role i.e userRole. 
			//do we need to confirm the availability if user Role. 
			//does it exist or not? 
			//else throw the exception
			
			Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(()->new RuntimeException("Error: Role  Not Found"));
			roles.add(userRole);
		} else {
			 strRoles.forEach(role -> {
			        switch (role) {
			        case "admin":
			          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
			              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			          roles.add(adminRole);

			          break;
			        case "mod":
			          Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
			              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			          roles.add(modRole);

			          break;
			        default:
			          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
			              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			          roles.add(userRole);
			        }
			      });
		}
		user.setRoles(roles);
		userRepository.save(user);
		return ResponseEntity.ok(new MessageResponse("user Registered Successfully"));
	}
}
