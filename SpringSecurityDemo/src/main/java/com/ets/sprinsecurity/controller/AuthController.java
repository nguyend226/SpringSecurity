package com.ets.sprinsecurity.controller;

import java.util.*;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ets.sprinsecurity.dto.User;
import com.ets.sprinsecurity.enums.ERole;
import com.ets.sprinsecurity.dto.Role;
import com.ets.sprinsecurity.payload.request.SignupRequest;
import com.ets.sprinsecurity.repo.RoleRepository;
import com.ets.sprinsecurity.repo.UserRepository;
import com.ets.sprinsecurity.response.MessageResponse;

@CrossOrigin("*")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepository;
	
	
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid SignupRequest signupRequest){
		
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
		
		User user = new User(signupRequest.getUsername(),signupRequest.getEmail(),signupRequest.getPassword());
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
