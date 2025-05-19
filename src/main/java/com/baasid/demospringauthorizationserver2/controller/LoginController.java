package com.baasid.demospringauthorizationserver2.controller;

import com.baasid.demospringauthorizationserver2.model.LoginReq;
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
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
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

      // 驗證成功：做登入處理（設 Cookie, Session, JWT...）
      // 如果是利用 AuthenticationManager，會依照預設(除非有重新覆寫 Service，再去做一次驗證
      // 以這個例子，會把使用者的帳密再拿去驗證一次(跟 UserDetailsService) 這邊有關係
      // Authentication authentication = authenticationManager.authenticate(
      //        new UsernamePasswordAuthenticationToken(userInfo.getUsername(), userInfo.getPassword())
      // );

      // 或是直接建立一個，已通過驗證的 Authentication 物件
      Map<String, String> userInfoMap = new HashMap<>();
      userInfoMap.put("username", userInfo.getUsername());

      List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
      Authentication authentication = new UsernamePasswordAuthenticationToken(userInfo.getUsername(), null, authorities);

      ((AbstractAuthenticationToken) authentication).setDetails(userInfoMap);

      SecurityContext context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(authentication);
      SecurityContextHolder.setContext(context);
      request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

      // 轉跳到登入成功頁面
      response.sendRedirect("/home.html");
    } else {
      // 驗證失敗
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "帳號密碼錯誤");
    }

    return ResponseEntity.ok().build();
  }
}
