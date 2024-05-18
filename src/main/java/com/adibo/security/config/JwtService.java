package com.adibo.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_Key="404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    public String extractUsername(String token) {

        return extractClaims(token,Claims::getSubject);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
        //extraClaims:if i want to pass authorities or pass any information i want to store in token
        return Jwts
                .builder()
                .setClaims(extraClaims)
                //as username is the unique in or app
                .setSubject(userDetails.getUsername())
                //when the claim was created and this information will help to calc the expiration date
                .setIssuedAt(new Date(System.currentTimeMillis()))
                //will be valid for 24 hours and 1000 mills
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                //like which key that we want to use to sign this token and the signing key
                //is the get signing key method
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                //which will generate and return the token
                .compact();
    }
    public boolean isTokenValid(String token,UserDetails userDetails){
        //the userDetails is here because we want to validate if this token which sent belong
        //to this user
        final String username=extractUsername(token);
        return (username.equals(userDetails.getUsername()))&&!isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        /**
         * setSigningKey:-
         * the secret that is used to digitally sign the JWT the signing key is
         * used to create the signature part of the jwt which is used to verify
         * that the sender of the jwt is who it claims to be and ensure that the message
         * wasn't change along the way so we want to ensure that the same person
         * or the same client that is sending this jwt key is the one that claims who to be
         * */
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public <T>T extractClaims(String token, Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Key getSignInKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_Key);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
