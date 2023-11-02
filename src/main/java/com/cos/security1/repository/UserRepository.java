package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
// 어노테이션 없어도 IoC 된다.
public interface UserRepository extends JpaRepository<User, Integer> {
    //findBy규칙 -> Username 문법
    // select * from user where username = ?
    public User findByUsername(String username);
}
