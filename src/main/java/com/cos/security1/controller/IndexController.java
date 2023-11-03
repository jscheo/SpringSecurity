package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

// 원래 큰 범위의 session 안에 스프링 시큐리티만가 관리하는 session 영역이 존재
// 시큐리티세션에는 Authentication 객체가 존재한다. 이 값을 필요할 떄 마다 Di (dependency injection)
// 을 통해 값을 꺼내올 수 있는데 Authentication 안에 들어갈 수 있는 두 가지의 타입이 존재
// 1.UserDetails(일반 로그인) 2.OAuth2User(sns 로그인) 가 있다.

@Controller // view를 리턴하겠다
public class IndexController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    //  @AuthenticationPrincipal 세션정보에 접근할 수 있게한다.
    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails){// DI(의존성주입)
        System.out.println("/test/login==============");
        // 원래는 UserDetails 타입으로 다운캐스팅해야하지만 PrincipalDetails 에서 UserDetails을 임플리먼츠 했기 때문에 가능
        // 즉 UserDetails = PrincipalDetails 가 된다.
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication:" + principalDetails.getUser());

        System.out.println("userDetails:" + userDetails.getUser());
        return "세션 정보 확인하기";
    }
    // Authentication 타입으로 바로 user정보에 접근이 가능하다. 헌데 getPrincipal로 받게되면
    // 구글로그인인 경우 OAuth2User 타입으로 다운캐스팅을 해야지 값을 받아올 수 있다.
    // @AuthenticationPrincipal 어노테이션으로도 바로 접근이 가능한데 OAuth2User 타입으로 해야한다.
    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oAuth){// DI(의존성주입)
        System.out.println("/test/oauth/login==============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication:" + oAuth2User.getAttributes());
        System.out.println("oauth2User:" + oAuth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }
    @GetMapping({"", "/"})
    public String index(){
        //머스테치 기본폴더 src/main/resources/
        // 뷰리졸버 설정: templates(prefix).mustuche(suffix) 생략 가능
        return "index";
    }
    // OAuat 로그인을 해도 pricipalDetails 로 받을 수 있음
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails:" + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }
    // 스프링시큐리티 해당주소를 낚아챔 - SecurityConfig 파일 생성 후에는 작동 안함.
    @GetMapping("/loginForm")
    public  String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }
    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입 잘됨. 비밀번호 : 1234 => 시큐리티로 로그인을 할 수 없음. 이유는 패스워드가 암호화가 안되었기 때문
        return "redirect:/loginForm";
    }
    // 접근하는데 조건을 거는 어노테이션 시큐리티 컨피그의 어노테이션에 의해서 사용가능
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    // 여러개 걸고 싶을 때
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }
}
