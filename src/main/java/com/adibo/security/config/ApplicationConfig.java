package com.adibo.security.config;

import com.adibo.security.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private UserRepository repository;
    @Bean
    public UserDetailsService userDetailsService(){

       return username ->repository.findByEmail(username)
               .orElseThrow(()->new UsernameNotFoundException("User not found"));
    }
    @Bean
    public AuthenticationProvider authenticationProvider(){
        //is data access provider which responsible to fetch the user details and encode password
        DaoAuthenticationProvider authProvider=new DaoAuthenticationProvider();
        //to specify two properties first the userDetailsservice
        /**
         * we need to tell this authentication provider which user details service to user
         * in order to fetch info about our user because we might have multiple implem
         * about user details one for ex: getting info from the db another on a different
         * profile fetching the users from in-memory
         * */
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
    }
    /**
     * the one that responsible to manage the authentication
     * the AuthenticationManager have bunch of methods and one of them there is a method
     * that allow to authenticate user based or just using username or password
     * */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)throws Exception{
        return config.getAuthenticationManager();
    }

}
