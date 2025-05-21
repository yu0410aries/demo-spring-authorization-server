package com.r.demospringauthorizationserver2.config;

import com.r.demospringauthorizationserver2.mapper.CustomUserInfoMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityConfig {

    @Autowired
    CustomUserInfoMapper customUserInfoMapper;

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Spring Authorization Server 提供的設定器，用來自動配置授權端點、Token 端點、JWK Set 端點、OIDC Discovery 等
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())           // 當符合這些路徑時用這個 chain 處理
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())     // 要求這些路徑都要處於登入狀態才能用
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))    // 禁用這些路徑的 CSRF
                .with(authorizationServerConfigurer, configurer -> {
                    configurer.oidc(oidc -> oidc.userInfoEndpoint(userinfo -> userinfo.userInfoMapper(customUserInfoMapper.createCustomUserInfoMapper())));     // 啟用 OpenID Connect 支援 (用預設設定)，除了 OAuth2 授權碼，還有 ID Token、UserInfo、Discovery 端點等
                });

        http
                // 啟用 jwt 的 resource server 功能，允許驗證 Authorization: Bearer <token> 的請求 (ex. GET /userinfo) 需要帶 ID Token 的 JWT 才能用
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                .exceptionHandling(
                        // authenticationEntryPoint 用來定義「未通過驗證時的回應行為」
                        // 使用者想用受保護的 endpoint (/oauth2/authorize)，但還沒登入，就會觸發這個 AuthenticationEntryPoint
                        e -> e.authenticationEntryPoint(
                                // AuthenticationEntryPoint 這是一個 spring security 提供的 AuthenticationEntryPoint 實作，當使用者未登入時導向一個登入畫面
                                // 這邊表示，當未登入時會導向這個頁面
                                // 如果用的是 spring security 預設的 (http.formLogin(Customizer.withDefaults());) 要設定 "/login"
                                new LoginUrlAuthenticationEntryPoint("/sso/login.html")
                        ));

        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable); // 關閉 CSRF
        // 1. 啟用 Spring Security 的內建登入頁
        // 2. 表單會送到 /login 處理帳號密碼驗證
        // 3. 這會讓未登入的請求自動跳到內建登入頁
        // http.formLogin(Customizer.withDefaults());

        // 不使用預設的 /login 頁面，改用自己寫的
        http.formLogin(form -> form
                .loginPage("/sso/login.html")
                // 如果後續「登入」的動作要讓 spring security 自己做的話，在頁面上設定 form post 打到這個位置，在這邊設定 loginProcessingUrl
                // <form method="post" action="/sso/login">
                //  <input type="text" name="username">
                //  <input type="password" name="password">
                //  <button type="submit">登入</button>
                // </form>
                // 可以讓 spring security 去攔截這個位置，然後根據傳回來的 username 跟 password 去驗證，並在成功之後建立 SecurityContext
                // 並成功後登入成功頁，失敗後導向失敗頁
                // .loginProcessingUrl("/sso/login")
                // 成功後導向此
                // .defaultSuccessUrl("/home", true)
                // 失敗後導向此
                // .failureUrl("/sso/login.html?error=true")
        );

        // 其他的所有請求都要是「已登入」才能用
        http.authorizeHttpRequests(a ->
                a.requestMatchers("/sso/login.html", "/js/**", "/css/**").permitAll()   // 因為在沒登入的狀況下會導到 /sso/login/html，
                .requestMatchers("/login").permitAll()  // 因為會把 login 的 api 放在 /login 的路徑，所以要允許這個路徑
                .anyRequest().authenticated());
        return http.build();
    }
}
