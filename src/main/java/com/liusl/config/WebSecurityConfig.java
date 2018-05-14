package com.liusl.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @auther liusl12
 * @date 2018/5/9.
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
    /**
     * 自定义配置
     * @param http
     * @throws Exception
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception{
//        http
//                .authorizeRequests()
//                .antMatchers("/css/**","/js/**","/fonts/**","/index")   //匹配的这些静态资源都可以访问，无需认证
//                .permitAll()
//                .antMatchers("/users/**").hasRole("USER")           //需要“USER”角色才能访问
//                .antMatchers("/admins/**").hasRole("ADMIN") ;        //需要“ADMIN”角色才能访问
////                .and()
////                .formLogin()                                        //基于form表单登录认证
////                .loginPage("/login")                                //指定登录页面
////                .failureUrl("/login-error");                        //指定登录失败跳转页面
//    }
//
//    /**
//     * 创建一个UserDetailsService Bean，添加两个内存用户
//     * @return
//     */
//    @Bean
//    public UserDetailsService userDetailsService(){
//        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();   //在内存中存放用户信息
//        inMemoryUserDetailsManager.createUser(User.withUsername("liusl12").password("123456").roles("USER").build());   //在内存中添加用户liusl12,设置密码是123456，用户角色为“USER”
//        inMemoryUserDetailsManager.createUser(User.withUsername("admin").password("admin").roles("ADMIN").build());     //在内存中添加用户admin,设置密码是admin，用户角色为“ADMIN”
//        return inMemoryUserDetailsManager;
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService());
//    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("admin").password("admin").roles("USER");
    }

}
