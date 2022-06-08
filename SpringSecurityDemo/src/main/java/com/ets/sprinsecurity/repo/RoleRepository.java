package com.ets.sprinsecurity.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ets.sprinsecurity.dto.Role;
import com.ets.sprinsecurity.enums.ERole;

public interface RoleRepository extends JpaRepository<Role, Long>{
	Optional<Role> findByName(ERole name);
}
