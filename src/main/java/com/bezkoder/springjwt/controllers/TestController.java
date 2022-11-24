package com.bezkoder.springjwt.controllers;

import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
  @Autowired
  private UserRepository userRepository;

  @Autowired
  private RoleRepository roleRepository;
  @GetMapping("/all")
  public String allAccess(Principal all) {

    String user = "NOM D'UTILISATEUR: " + userRepository.findByUsername(all.getName()).get().getUsername() + "  EMAIL:  "+
            userRepository.findByUsername(all.getName()).get().getEmail();
    return "Bienvenue, " + user;
  }

  @GetMapping("/user")
  @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
  public String userAccess(Principal user)
  {

    return "Bienvenue, " + userRepository.findByUsername(user.getName()).get().getUsername() +
            roleRepository.findByName(ERole.ROLE_USER).get().getName();
  }

  @GetMapping("/mod")
  @PreAuthorize("hasRole('MODERATOR')")
  public String moderatorAccess() {
    return "Moderator Board.";
  }

  @GetMapping("/admin")
  @PreAuthorize("hasRole('ADMIN')")
  public String adminAccess(Principal admin ) {

    return "Bienvenue " + " "+ userRepository.findByUsername(admin.getName()).get().getUsername()  + " "+
            roleRepository.findByName(ERole.ROLE_ADMIN).get().getName()
            ;
  }
}
