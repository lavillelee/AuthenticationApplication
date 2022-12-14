package com.example.AuthenticationApp.repository;

import com.example.AuthenticationApp.model.ERole;
import com.example.AuthenticationApp.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
