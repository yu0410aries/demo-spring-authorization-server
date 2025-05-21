package com.r.demospringauthorizationserver2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.time.Duration;

@Configuration
public class AppConfig {

  DataSource dataSource;

  public AppConfig(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  // 建立預設的使用者
  @Bean
  public UserDetailsService userDetailsService() {

    // 改用 jdbc 管理帳號資訊
    JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

    // 沒有 admin 帳號的話預設建立一個
    if (!userDetailsManager.userExists("admin")) {
      UserDetails user = User.withUsername("admin")
              .password("{noop}12345")
              .roles("USER", "ADMIN")
              .build();
      userDetailsManager.createUser(user);
      // return new InMemoryUserDetailsManager(user);
    }

    // user 資訊改存在 db
    return userDetailsManager;
  }

    // 註冊一個 client (放記憶體裡)
  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

    JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

    // 沒有預設的 client 的話建立一個
    if (jdbcRegisteredClientRepository.findByClientId("client") == null ) {
      RegisteredClient registeredClient = RegisteredClient
              .withId("rhkg3")
              .clientId("client")
              .clientSecret("{noop}secret")
              .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
              .redirectUri("http://localhost:8081")
              .scope("openid")
              .tokenSettings(
                      TokenSettings.builder()
                              .accessTokenTimeToLive(Duration.ofHours(6))
                              .build()
              )
              .clientSettings(
                      ClientSettings.builder()
                              .requireAuthorizationConsent(true)    // 啟用授權頁面
                              // .requireProofKey(false)
                              .build()
              )
              .build();
      jdbcRegisteredClientRepository.save(registeredClient);
    }

    // client 資訊改存在 db
    // return new InMemoryRegisteredClientRepository(registeredClient);
    return jdbcRegisteredClientRepository;
  }
}
