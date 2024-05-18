package com.adibo.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
/*
it will create a constructor using any final field that we declare
inside JwtAuthenticationFilter class
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    /* i want this class to be active everytime it get a request
    * so i extends  OncePerRequestFilter
    * */
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain
                        )throws ServletException, IOException {
        /*
        because when we make a call we need to pass the JWT authentication token
        within the header
        ->so the header will be called Authorization
        this is the header that contain the JWT or the Bearer token
         */
        final String authHeader=request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        /*
        here to check the jwt token
        if null or don't start with Bearer as any token should be start with Bearer
         */
        if(authHeader==null||!authHeader.startsWith("Bearer")){
            //as i need to pass it to the next filter
            filterChain.doFilter(request,response);
            return;
        }
        //to extract the token form the header
        //and i want to count from 7 as the length of Bearer is 6 so i want to start from index 7
        jwt=authHeader.substring(7);

        /*
        * //to do extract the userEmail from JWT token ;
        * i will implement a class that manipulate this
        * through -> JwtService class which i will autowired it
        * */
        userEmail=jwtService.extractUsername(jwt);
        //if userEmail and user is not authenticated
        if (userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            //SecurityContextHolder.getContext().getAuthentication()==null ->that user not connected yet or authenticated
            //get the userDetails from the database
            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt,userDetails)){
                UsernamePasswordAuthenticationToken authToken=
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,//as i don't send a credentials
                                userDetails.getAuthorities()
                                );
                //here we enforce this authentication token with the details of our request
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //here to update the security context holder or to update the authentication token
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);

    }


}
