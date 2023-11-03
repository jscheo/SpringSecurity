package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// 일반적인 로그인 api 사용 순서
// 1.코드받기(인증) 2.엑세스토큰(권한) 3.사용자 프로필 정보를 가져온다.
// 4-1.그 정보를 토대로 회원가입을 자동으로 진행시키키도함.
// 4-2.(이메일,전화번호,이름,아이디)쇼핑몰 ->(집주소),백화점->(vip등급, 일반등급 등)이 필요하면 회원가입을 따로 진행해야한다.
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig)가 스프링 필터체인에 등록이 됩니다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;
    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
//                .usernameParameter("username2") // 파라미터 이름을 바꾸고 싶으면 사용
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줍니다.
                .defaultSuccessUrl("/")// 처음 리턴주소이고 두번째로 다시 로그인해서 하게 되면 잡혀왔던 주소로 로그인 후 이동하게 된다.
                                        // 인터셉터 같은 느낌
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint() // 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip.코드x(엑세스토큰+사용자프로필정보 까지 가져온다.)
                .userService(principalOauth2UserService);

    }
}
