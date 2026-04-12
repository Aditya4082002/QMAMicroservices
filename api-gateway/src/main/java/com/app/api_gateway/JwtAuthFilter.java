package com.app.api_gateway;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    // Must match the secret in auth-service JwtUtil
    private final String SECRET = "mysecretkeymysecretkeymysecretkey123456";
    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(authHeader.substring(7))
                        .getBody();

                String username = claims.getSubject();

                ServerWebExchange modifiedExchange = exchange.mutate()
                        .request(exchange.getRequest()
                                .mutate()
                                .header("X-User-Name", username)
                                .build())
                        .build();

                return chain.filter(modifiedExchange);

            } catch (JwtException e) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }

        // No token → guest user → continue without username
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}