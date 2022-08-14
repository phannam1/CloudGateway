package com.gateway.sercurity;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

import java.net.URI;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;



import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter implements GlobalFilter {
	
	 private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);
	 
    @Value("${jwt.app.jwtSecret}")
    private String jwtSecret;
	@Autowired
	private RouterValidator routerValidator;// custom route validator
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		Log log = LogFactory.getLog(getClass());

		ServerHttpRequest request = exchange.getRequest();
		// Check da login hay dg login
		if (routerValidator.isSecured.test(request)) {
			if (this.isAuthMissing(request))
				return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);
			// da login Check token
			if (!redirectCheckToken(request, exchange, chain))
				return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);
			// chuyen neu check ok
			ServerHttpRequest originalUris = exchange.getRequest();
			if (originalUris != null) {
//				URI originalUri = originalUris.iterator().next();

				Route route = exchange.getAttribute(GATEWAY_ROUTE_ATTR);

				URI routeUri = exchange.getAttribute(GATEWAY_REQUEST_URL_ATTR);
				log.info("Incoming request " + originalUris.getURI().toString() + " is routed to id: " + route.getId()
						+ ", uri:" + routeUri);
			}
		}
		return chain.filter(exchange);
	}

	private boolean redirectCheckToken(ServerHttpRequest request, ServerWebExchange exchange,
			GatewayFilterChain chain) {
		final String token = getTokenFromRequest(request);
		if (token != null ) {
			if(validateJwtToken(token)) {
				return true;
			}
		}
		return false;

	}
	private boolean validateJwtToken(String authToken) {
	        try {
	            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
	            return true;
	        } catch (io.jsonwebtoken.SignatureException e) {
	            logger.error("Invalid JWT signature: {}", e.getMessage());
	        } catch (MalformedJwtException e) {
	            logger.error("Invalid JWT token: {}", e.getMessage());
	        } catch (ExpiredJwtException e) {
	            logger.error("JWT token is expired: {}", e.getMessage());
	        } catch (UnsupportedJwtException e) {
	            logger.error("JWT token is unsupported: {}", e.getMessage());
	        } catch (IllegalArgumentException e) {
	            logger.error("JWT claims string is empty: {}", e.getMessage());
	        }

	        return false;
	    }

	private boolean isAuthMissing(ServerHttpRequest request) {
		return !request.getHeaders().containsKey("Authorization");
	}

	private Mono<Void> onError(ServerWebExchange exchange, String string, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		return response.setComplete();
	}
	private String getTokenFromRequest(ServerHttpRequest request) {
		final String token = request.getHeaders().getOrEmpty("Authorization").get(0);

        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7, token.length());
        }

        return null;
    }

}
