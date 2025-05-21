package com.r.demospringauthorizationserver2.mapper;

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
      // Map<String, Object> attributes = context.getAuthorization().getAttributes();

      String userid = context.getAuthorization().getPrincipalName();

      // 此處透過 userid 去 db 查出 user 的資料

      // 拿 scope，要用來判斷回傳哪些資料
      context.getAuthorization().getAuthorizedScopes();

      Map<String, Object> claims = new HashMap<>();
      claims.put("userid", userid);
      claims.put("email", "example_user_email@gmail.com");

      return new OidcUserInfo(claims);
    };
  }
}
