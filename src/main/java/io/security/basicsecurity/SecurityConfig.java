package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@EnableWebSecurity  //웹보안
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가 설정
        http.authorizeRequests() //http 방식 요청식 보안검사
                .anyRequest().authenticated(); //어떤요청에도 인증을 받음
        //인증 정책
        http.formLogin()//폼인증방식
//        .??("/loginPage") //사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")  // 로그인 성공 후 이동 페이지
                .failureUrl("/loginPage") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") //아이디 파라미터 명 설정
                .passwordParameter("passwd") //패스워드 파라미터 명 설정
                .loginProcessingUrl("/login_proc") //로그인 Form Action Url
//                .successHandler(loginSuccesHandler()) //로그인 성공후 핸들러
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    System.out.println("authentication"+authentication.getName());
                    httpServletResponse.sendRedirect("/");
                }) //로그인 성공후 핸들러
//                .failureHandler(loginFailureHandler()) //로그인 실패 후 핸들러
                  .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                      System.out.println("exception "+e.getMessage());
                      httpServletResponse.sendRedirect("/login");
                  }) //로그인 실패 후 핸들러
        .permitAll() //로그인 페이지는 누구나 접근 가능하도록
        ;

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login") //기본적으로 로그아웃은  Post방식 Get방식을 별도로 처리
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession httpSession = httpServletRequest.getSession();
                        httpSession.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")
        ;

    }
}
