package com.cos.security1.config.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 시큐리티 session을 만들어줍니다. (Security ContextHolder)
// 오브젝트 => Authentication 타입 객체 여야함
// Authentication 안에 User 정보가 있어야 됨.
// User오브젝트타입 => UserDetails 타입 객체 여야됨

import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

// 구글 로그인 등의 로그인과 일반로그인할 때 유저 정보가 담기는 객체타입이 다른데
// 이걸 그때마다 구분지어서 하기는 힘들다 즉 두 가지의 객체를 하나의 객체 타입에 implements를 해둔다면
// 그 객체 하나만 Authentication 안에 넣어주게 되면 상관이 없어지는 원리 두 가지 타입 중 아무거나 상관없으니까
// 그러하여 PrincipalDetails 이 객체 안에 두 타입 객체를 implements 해서 overriding 하여 사용할 수 있다.
@Data
// Security Session => Authentication => UserDetails
public class PrincipalDetails implements UserDetails, OAuth2User {
    // user object 를 선언 해놨기 때문에 principal 객체에 담을 수 있는 것이다.
    private User user;// 컴포지션
    private Map<String, Object> attributes;

    // 일반 로그인 시 생성자
    public PrincipalDetails(User user){
        this.user =user;
    }

    //OAuth 로그인 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes){
        this.user =user;
        this.attributes =attributes;
    }

    // 해당 User의 권한을 리턴하는 곳!
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        //우리 사이트에 1년동안 회원이 로그인을 안하면 휴먼 계정으로 하기로 함.
        //현재시간 - 로그인시간 => 1년을 최과하면 return false;
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }
    @Override
    public String getName() {
        return null;
    }
}
