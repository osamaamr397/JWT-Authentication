package com.adibo.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationProvider;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * what i will need to do because as the startup or at the app startup spring security will
     * try to look for bean of type security filter chain and this sec filter chain is the bean
     * responsible of configuring all the http sec of our app so i will create a bean
     * */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        /**
         * within security we can choose and decide what are the url and the pathways
         * that we want to secure but of course within every app we have always a white list
         * white lis -> means that we have some endpoints that they do not require any authentication
         * or any tokens but which are open
         * this will through ->authorizeHttpRequests()
         * any url inside i request matcher i don't to auth it
         * but starting from .permitAll()
         *                 .anyRequest()
         *                 .authenticated()
         *                 i want to auth it
         * */
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
                    /*
                ->because i want to excute this filter before the filter called username password auth
                    because as you remember when we implemented the jwt auth filter we check everything
                    and then we set the sec context we update the sec context holder and
                    after that we will be calling the username password auth filter so i will
                    use jwtAuthFilter
                */

                /**
                 * the meaning of session management:-
                 * we said that when we implemented the filter chain we want a once
                 * prerequest filter means->every request should be authenticated
                 * this mean that we should not store the auth state or the session state
                 * should not be stored so this the session should be statless and this
                 * will help us ensure that each request should be auth
                 * */
        return http.build();
    }
}
