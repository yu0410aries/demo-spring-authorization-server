package com.r.demospringauthorizationserver2.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    Object principal = authentication.getPrincipal();

    // 處理 token 類型為 UsernamePasswordAuthenticationToken 時
    if (authentication instanceof UsernamePasswordAuthenticationToken) {
      // 登入驗證判斷也可以寫這，比方說驗證帳號密碼是不是正確，而帳號密碼則需要則是透過 authentication 帶進來
      // 因為如果是直接用預設的 provider 像是 DaoAuthenticationProvider，這些 provider 都包含了完整的預設的
      // 檢查帳號密碼、是否過期、是否鎖定的判斷方式，當然如果要這樣用的話，針對 user 的設計，包括 db schema 都要符
      // 合他的設計，比方說 DaoAuthenticationProvider 這個 provider 就是用 org.springframework.security.core.userdetails.UserDetails
      // 這個物件去搭配完成這些判斷的動作，其他的常見的還有
      // DaoAuthenticationProvider	支援帳號密碼（搭配 UserDetailsService）✅
      // LdapAuthenticationProvider	支援 LDAP 登入
      // PreAuthenticatedAuthenticationProvider	處理 SSO、憑證等已驗證的 token
      // JwtAuthenticationProvider（搭配 Resource Server）	處理 bearer token（JWT）驗證
      if (principal instanceof Map) {
        @SuppressWarnings("unchecked")
        Map<String, String> userInfo = (Map<String, String>) principal;
        return new UsernamePasswordAuthenticationToken(userInfo, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
      }
    }

    throw new BadCredentialsException("Invalid certificate data");
  }

  // 設定這個 AuthenticationProvider 支援哪些 AuthenticationToken
  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    // || PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
  }
}