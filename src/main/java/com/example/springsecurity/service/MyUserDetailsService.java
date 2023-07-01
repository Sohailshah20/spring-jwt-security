package com.example.springsecurity.service;

import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.user.SecurityUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public MyUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
         var user = userRepository.findByEmail(username);
         return user.map(SecurityUser::new)
                 .orElseThrow(() -> new UsernameNotFoundException("username not found"));

    }
}
