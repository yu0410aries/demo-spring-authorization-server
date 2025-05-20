package com.baasid.demospringauthorizationserver2.mapper;

import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class CustomUserInfoMapper {
  @Bean
  public Function<OidcUserInfoAuthenticationContext, OidcUserInfo> createCustomUserInfoMapper() {
    return context -> {
      Map<String, Object> attributes = context.getAuthorization().getAttributes();
      Map<String, Object> userInfo = (Map<String, Object>) attributes.get("userInfo");

      Map<String, Object> claims = new HashMap<>();
      claims.put("sub", context.getAuthorization().getPrincipalName());

      if (userInfo != null) {
        claims.putAll(userInfo);
      }

      return new OidcUserInfo(claims);
    };
  }
}
