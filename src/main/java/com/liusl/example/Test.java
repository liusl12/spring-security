package com.liusl.example;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * @auther liusl12
 * @date 2018/5/11.
 */
public class Test {
    private static AuthenticationManager authenticationManager = new SampleAuthenticationManager();    //创建AuthenticationManager对象
    public static void main(String[] args) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.println("Please enter your username:");
            String name = in.readLine();
            System.out.println("Please enter your password:");
            String password = in.readLine();
            try {
                Authentication authentication = new UsernamePasswordAuthenticationToken(name, password);//将用户信息封装成UsernamePasswordAuthenticationToken
                Authentication result = authenticationManager.authenticate(authentication); //认证用户
                SecurityContextHolder.getContext().setAuthentication(result);   //将认证信息装入上下文中
                break;
            }
            catch (AuthenticationException e){
                System.out.println("Authentication failed "+ e.getMessage());
            }
        }
        System.out.println("Successfully authentication.Security context contains: " + SecurityContextHolder.getContext().getAuthentication());
    }
}

/**
 * 简单重写了AuthenticationManager，认证的方式为用户名和密码相等
 */
class SampleAuthenticationManager implements AuthenticationManager {
    static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();
    static {
        AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
    }
    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        if (auth.getName().equals(auth.getCredentials())) {
            return new UsernamePasswordAuthenticationToken(auth.getName(),
                    auth.getCredentials(), AUTHORITIES);
        }
        throw new BadCredentialsException("Bad Credentials");
    }
}
