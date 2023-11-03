package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
//@Configuration
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로 부터 받은 userReauest 데이터에 대한 후 처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        System.out.println("getAccessToken:" +userRequest.getAccessToken());
        // registrationId 로 어떤 Oauth(google)로 로그인했는지 알 수 있음
        System.out.println("getClientRegistration:" +userRequest.getClientRegistration());
        System.out.println("getAdditionalParameters:" +userRequest.getAdditionalParameters());


        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 구글로그인 버튼 클릭 ->로그인창->로그인 완료->code리턴(Oauth-client라이브러리) ->AccessToken 요청
        // 위에까지가 userRequest 정보 ->loadUser 함수->회원프로필 받음(from google>
        System.out.println("getAttributes:" + oAuth2User.getAttributes());

        // 회원가입을 강제로 진행 Authentication 객체로 들어가게 됨
        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider+"_"+providerId; // google_23442432123
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            System.out.println("구글로그인이 최초입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else{
            System.out.println("구글 로그인 이미 했습니다.");
        }


        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
