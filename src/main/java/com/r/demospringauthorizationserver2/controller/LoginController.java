package com.r.demospringauthorizationserver2.controller;

import com.r.demospringauthorizationserver2.model.LoginReq;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class LoginController {

  @Autowired
  private AuthenticationManager authenticationManager;

  @PostMapping("login")
  public ResponseEntity<Void> login(@RequestBody LoginReq userInfo,
                              HttpSession session,
                              HttpServletRequest request,
                              HttpServletResponse response) throws IOException {

    if ("admin".equals(userInfo.getUsername()) && "12345".equals(userInfo.getPassword())) {

       Map<String, String> userInfoMap = new HashMap<>();
       userInfoMap.put("userid", userInfo.getUsername());

      // 驗證成功：做登入處理（設 Cookie, Session, JWT...）
      // 如果是利用 AuthenticationManager，會依照預設(除非有重新覆寫 Service，再去做一次驗證
      // 以這個例子，會把使用者的帳密再拿去驗證一次(跟 UserDetailsService) 這邊有關係
       Authentication authentication = authenticationManager.authenticate(
              // 把要變成這個 token 的 sub 的值放進去，通常是指這個 user 的識別key
              new UsernamePasswordAuthenticationToken(userInfoMap, userInfo.getPassword())
       );

      // 或是直接建立一個，已通過驗證的 Authentication 物件
      // 賦與使用者權限角色
      // List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
      // userInfo.getUsername 會變成這個 token 的 sub
      // Authentication authentication = new UsernamePasswordAuthenticationToken(userInfo.getUsername(), null, authorities);

      // 在這邊，把額外的使用者資訊，塞到 authentication 裡，後面取 userinfo 時可以直接從 authenticaion 取出
      // 不過要配合重寫 OAuth2AuthorizationService 並且比較不是常用做法，不是這篇主要目的
      // Map<String, String> userInfoDetailMap = new HashMap<>();
      // userInfoMap.put("username", userInfo.getUsername());
      // userInfoMap.put("email", "example_user_email@gmail.com");
      // ((AbstractAuthenticationToken) authentication).setDetails(userInfoDetailMap);

      SecurityContext context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(authentication);
      SecurityContextHolder.setContext(context);
      request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

      // 登入成功後，接轉回原本的 oauth 的流程，跳轉回原本的 oauth/authorize 那個 uri，讓原本的流程接手
      response.sendRedirect("/sso/home.html");
    } else {
      // 驗證失敗
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "帳號密碼錯誤");
    }

    return ResponseEntity.ok().build();
  }
}
