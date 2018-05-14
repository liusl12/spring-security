# Spring Security

> 核心类解析

## 架构概览图

![架构概览图](http://ov0zuistv.bkt.clouddn.com/spring%20security%20architecture.png) 

## SecurityContextHolder

> SecurityContextHolder用于存储安全上下文（security context）的信息。当前操作的用户是谁，该用户是否已经被认证，他拥有哪些角色权限…这些都被保存在SecurityContextHolder中。 

**获取当前用户的信息**

![1526005147826](C:\Users\liusl12\AppData\Local\Temp\1526005147826.png)

getAuthentication()返回了认证信息，再次getPrincipal()返回了身份信息，UserDetails便是Spring对身份信息封装的一个接口。Authentication和UserDetails的介绍在下面的小节具体讲解，本节重要的内容是介绍SecurityContextHolder这个容器。



## Authentication

> Authentication在spring security中是最高级别的身份/认证的抽象。 

![1526005236716](C:\Users\liusl12\AppData\Local\Temp\1526005236716.png)



+ getAuthorities():	权限信息列表
+ getCredentials():   密码信息，用户输入的密码字符串，再认证通过后会被移除，保障安全
+ getDetails():   细节信息，web应用中的实现接口通常为 WebAuthenticationDetails，它记录了访问者的ip地址和sessionId的值。 
+ getPrincipal():   **获取身份信息，大部分情况返回的是UserDetails接口的实现类**

## Spring Security 是如何完成身份认证的？

1. 用户名和密码被过滤器获取到，封装成Authentication,通常情况下是*UsernamePasswordAuthenticationToken*这个实现类。 
2. AuthenticationManager 身份管理器负责验证这个Authentication 
3. 认证成功后，AuthenticationManager身份管理器返回一个被填充满了信息的（包括上面提到的权限信息，身份信息，细节信息，但密码通常会被移除）Authentication实例。 
4. SecurityContextHolder安全上下文容器将第3步填充了信息的Authentication，通过SecurityContextHolder.getContext().setAuthentication(…)方法，设置到其中。 

下面是一个简单的例子，模拟了该过程：

```java
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
```

##AuthenticationManager

> AuthenticationManager是认证相关的核心接口。是认证的入口

因为在实际需求中，我们可能会允许用户使用用户名+密码登录，同时允许用户使用邮箱+密码，手机号码+密码登录，甚至，可能允许用户使用指纹登录（还有这样的操作？没想到吧），所以说AuthenticationManager一般不直接认证，AuthenticationManager接口的常用实现类ProviderManager 内部会维护一个List<AuthenticationProvider>列表，存放多种认证方式，实际上这是**委托者模式**的应用（Delegate）。也就是说，核心的认证入口始终只有一个：AuthenticationManager，不同的认证方式：用户名+密码（UsernamePasswordAuthenticationToken），邮箱+密码，手机号码+密码登录则对应了三个AuthenticationProvider。这样一来四不四就好理解多了？熟悉shiro的朋友可以把AuthenticationProvider理解成Realm。在默认策略下，只需要通过一个AuthenticationProvider的认证，即可被认为是登录成功。 

AuthenticationManager有几个实现类：

![1526008550596](C:\Users\liusl12\AppData\Local\Temp\1526008550596.png)

![1526009342267](C:\Users\liusl12\AppData\Local\Temp\1526009342267.png)

ProviderManager 中的List，会依照次序去认证，认证成功则立即返回，若认证失败则返回null，下一个AuthenticationProvider会继续尝试认证，如果所有认证器都无法认证成功，则ProviderManager 会抛出一个ProviderNotFoundException异常。 

到这里，如果不纠结于AuthenticationProvider的实现细节以及安全相关的过滤器，认证相关的核心类其实都已经介绍完毕了：身份信息的存放容器SecurityContextHolder，*身份信息的抽象Authentication*，身份认证器AuthenticationManager及其认证流程。姑且在这里做一个分隔线。下面来介绍下AuthenticationProvider接口的具体实现。

##DaoAuthenticationProvider 

先来看看几个方法：

*retrieveUser*

```java
protected final UserDetails retrieveUser(String username,
      UsernamePasswordAuthenticationToken authentication)
      throws AuthenticationException {
   prepareTimingAttackProtection();
   try {
      UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
      if (loadedUser == null) {
         throw new InternalAuthenticationServiceException(
               "UserDetailsService returned null, which is an interface contract violation");
      }
      return loadedUser;
   }
   catch (UsernameNotFoundException ex) {
      mitigateAgainstTimingAttack(authentication);
      throw ex;
   }
   catch (InternalAuthenticationServiceException ex) {
      throw ex;
   }
   catch (Exception ex) {
      throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
   }
}
```

通过前台传过来的用户名查询存储在数据库中的用户信息并封装成UserDetails



*additionalAuthenticationChecks*

```java
@SuppressWarnings("deprecation")
protected void additionalAuthenticationChecks(UserDetails userDetails,
      UsernamePasswordAuthenticationToken authentication)
      throws AuthenticationException {
   if (authentication.getCredentials() == null) {
      logger.debug("Authentication failed: no credentials provided");

      throw new BadCredentialsException(messages.getMessage(
            "AbstractUserDetailsAuthenticationProvider.badCredentials",
            "Bad credentials"));
   }

   String presentedPassword = authentication.getCredentials().toString();

   if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
      logger.debug("Authentication failed: password does not match stored value");

      throw new BadCredentialsException(messages.getMessage(
            "AbstractUserDetailsAuthenticationProvider.badCredentials",
            "Bad credentials"));
   }
}
```

通过retrieveUser查到的数据库中的用户名密码和前台的密码进行校验，如果成功则认证成功，否则失败

##UserDetails与UserDetailsService

> 上面不断提到了UserDetails这个接口，它代表了最详细的用户信息，这个接口涵盖了一些必要的**用户信息字段**，具体的实现类对它进行了扩展。 

```java
public interface UserDetails extends Serializable {
	Collection<? extends GrantedAuthority> getAuthorities();
	String getPassword();
	String getUsername();
	boolean isAccountNonExpired();
	boolean isAccountNonLocked();
	boolean isCredentialsNonExpired();
	boolean isEnabled();
}

```

它和Authentication接口很类似，比如它们都拥有username，authorities，区分他们也是本文的重点内容之一。**Authentication的getCredentials()与UserDetails中的getPassword()需要被区分对待，前者是用户提交的密码凭证，后者是用户正确的密码，认证器其实就是对这两者的比对。**Authentication中的getAuthorities()实际是由UserDetails的getAuthorities()传递而形成的。还记得Authentication接口中的getUserDetails()方法吗？其中的UserDetails用户详细信息便是经过了AuthenticationProvider之后被填充的。 



```java
public interface UserDetailsService {
   UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

UserDetailsService和AuthenticationProvider两者的职责常常被人们搞混，关于他们的问题在文档的FAQ和issues中屡见不鲜。记住一点即可，敲黑板！！！**UserDetailsService只负责从特定的地方（通常是数据库）加载用户信息，仅此而已，记住这一点，可以避免走很多弯路。**UserDetailsService常见的实现类有JdbcDaoImpl，InMemoryUserDetailsManager，前者从数据库加载用户，后者从内存中加载用户，也可以自己实现UserDetailsService，通常这更加灵活。 

## 核心配置解读

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http
          .authorizeRequests()
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
```

当配置了上述的javaconfig之后，我们的应用便具备了如下的功能：

+ 除了“/”,”/home”(首页),”/login”(登录),”/logout”(注销),之外，其他路径都需要认证。
+ 指定“/login”该路径为登录页面，当未认证的用户尝试访问任何受保护的资源时，都会跳转到“/login”。
+ 默认指定“/logout”为注销页面
+ 配置一个内存中的用户认证器，使用admin/admin作为用户名和密码，具有USER角色
+ 防止CSRF攻击
+ Session Fixation protection(可以参考我之前讲解Spring Session的文章，防止别人篡改sessionId)
+ Security Header(添加一系列和Header相关的控制)
  + HTTP Strict Transport Security for secure requests
  + 集成X-Content-Type-Options
  + 缓存控制
  + 集成X-XSS-Protection.aspx)
  + X-Frame-Options integration to help prevent Clickjacking(iframe被默认禁止使用)
+ 为Servlet API集成了如下的几个方法
  + HttpServletRequest#getRemoteUser())
  + HttpServletRequest.html#getUserPrincipal())
  + HttpServletRequest.html#isUserInRole(java.lang.String))
  + HttpServletRequest.html#login(java.lang.String, java.lang.String))
  + HttpServletRequest.html#logout())

### @EnableWebSecurity

我们自己定义的配置类WebSecurityConfig加上了@EnableWebSecurity注解，同时继承了WebSecurityConfigurerAdapter。你可能会在想谁的作用大一点，毫无疑问@EnableWebSecurity起到决定性的配置作用，它其实是个组合注解。 

```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import({ WebSecurityConfiguration.class,
      SpringWebMvcImportSelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

   /**
    * Controls debugging support for Spring Security. Default is false.
    * @return if true, enables debug support with Spring Security
    */
   boolean debug() default false;
}
```

@Import是springboot提供的用于引入外部的配置的注解，可以理解为：@EnableWebSecurity注解激活了@Import注解中包含的配置类。

<1> `SpringWebMvcImportSelector`的作用是判断当前的环境是否包含springmvc，因为spring security可以在非spring环境下使用，为了避免DispatcherServlet的重复配置，所以使用了这个注解来区分。

<2> `WebSecurityConfiguration`顾名思义，是用来配置web安全的，下面的小节会详细介绍。

<3> `@EnableGlobalAuthentication`注解的源码如下：

```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import(AuthenticationConfiguration.class)
@Configuration
public @interface EnableGlobalAuthentication {
}
```

注意点同样在@Import之中，它实际上激活了AuthenticationConfiguration这样的一个配置类，用来配置认证相关的核心类。

也就是说：@EnableWebSecurity完成的工作便是加载了**WebSecurityConfiguration，AuthenticationConfiguration**这两个核心配置类，也就此将spring security的职责划分为了配置安全信息，配置认证信息两部分。

###WebSecurityConfiguration

在这个配置类中，有一个非常重要的Bean被注册了 

```java
/**
 * Creates the Spring Security Filter Chain
 * @return
 * @throws Exception
 */
@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
public Filter springSecurityFilterChain() throws Exception {
   boolean hasConfigurers = webSecurityConfigurers != null
         && !webSecurityConfigurers.isEmpty();
   if (!hasConfigurers) {
      WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
            .postProcess(new WebSecurityConfigurerAdapter() {
            });
      webSecurity.apply(adapter);
   }
   return webSecurity.build();
}
```

在未使用springboot之前，大多数人都应该对“springSecurityFilterChain”这个名词不会陌生，他是spring security的核心过滤器，是整个认证的入口。在曾经的XML配置中，想要启用spring security，需要在web.xml中进行如下配置： 

```xml
<!-- Spring Security -->
   <filter>
       <filter-name>springSecurityFilterChain</filter-name>
       <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
   </filter>

   <filter-mapping>
       <filter-name>springSecurityFilterChain</filter-name>
       <url-pattern>/*</url-pattern>
   </filter-mapping>
```

而在springboot集成之后，这样的XML被java配置取代。WebSecurityConfiguration中完成了声明springSecurityFilterChain的作用，并且最终交给DelegatingFilterProxy这个代理类，负责拦截请求（注意DelegatingFilterProxy这个类不是spring security包中的，而是存在于web包中，spring使用了代理模式来实现安全过滤的解耦）。 

###AuthenticationConfiguration

```java
@Bean
public AuthenticationManagerBuilder authenticationManagerBuilder(
      ObjectPostProcessor<Object> objectPostProcessor, ApplicationContext context) {
   LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
   AuthenticationEventPublisher authenticationEventPublisher = getBeanOrNull(context, AuthenticationEventPublisher.class);

   DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, defaultPasswordEncoder);
   if (authenticationEventPublisher != null) {
      result.authenticationEventPublisher(authenticationEventPublisher);
   }
   return result;
}
```

```java
public AuthenticationManager getAuthenticationManager() throws Exception {
   if (this.authenticationManagerInitialized) {
      return this.authenticationManager;
   }
   AuthenticationManagerBuilder authBuilder = authenticationManagerBuilder(
         this.objectPostProcessor, this.applicationContext);
   if (this.buildingAuthenticationManager.getAndSet(true)) {
      return new AuthenticationManagerDelegator(authBuilder);
   }

   for (GlobalAuthenticationConfigurerAdapter config : globalAuthConfigurers) {
      authBuilder.apply(config);
   }

   authenticationManager = authBuilder.build();

   if (authenticationManager == null) {
      authenticationManager = getAuthenticationManagerBean();
   }

   this.authenticationManagerInitialized = true;
   return authenticationManager;
}
```

AuthenticationConfiguration的主要任务，便是负责生成全局的身份认证管理者AuthenticationManager。还记上面介绍了Spring Security的认证体系，AuthenticationManager便是最核心的身份认证管理器。 

### WebSecurityConfigurerAdapter

适配器模式在spring中被广泛的使用，在配置中使用Adapter的好处便是，我们可以选择性的配置想要修改的那一部分配置，而不用覆盖其他不相关的配置。WebSecurityConfigurerAdapter中我们可以选择自己想要修改的内容，来进行重写，而其提供了三个configure重载方法，是我们主要关心的： 

![1526267580521](C:\Users\liusl12\AppData\Local\Temp\1526267580521.png)

由参数就可以知道，分别是对AuthenticationManagerBuilder，WebSecurity，HttpSecurity进行个性化的配置。 

#### HttpSecurity常用配置

```java
@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfig extends WebSecurityConfigurerAdapter {
  
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/resources/**", "/signup", "/about").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                .failureForwardUrl("/login?error")
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/index")
                .permitAll()
                .and()
            .httpBasic()
                .disable();
    }
}
```

上述是一个使用Java Configuration配置HttpSecurity的典型配置，其中http作为根开始配置，每一个and()对应了一个模块的配置（等同于xml配置中的结束标签），并且and()返回了HttpSecurity本身，于是可以连续进行配置。他们配置的含义也非常容易通过变量本身来推测， 

- authorizeRequests()配置路径拦截，表明路径访问所对应的权限，角色，认证信息。
- formLogin()对应表单认证相关的配置
- logout()对应了注销相关的配置
- httpBasic()可以配置basic登录
- etc

他们分别代表了http请求相关的安全配置，这些配置项无一例外的返回了Configurer类，而所有的http相关配置可以通过查看HttpSecurity的主要方法得知： 

![1526267756848](C:\Users\liusl12\AppData\Local\Temp\1526267756848.png)

需要对http协议有一定的了解才能完全掌握所有的配置，不过，springboot和spring security的自动配置已经足够使用了。其中每一项Configurer（e.g.FormLoginConfigurer,CsrfConfigurer）都是HttpConfigurer的细化配置项。 

#### WebSecurityBuilder

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
            .antMatchers("/resources/**");
    }
}
```

#### AuthenticationManagerBuilder

 ```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .inMemoryAuthentication()
        .withUser("admin").password("admin").roles("USER");
}
 ```

想要在WebSecurityConfigurerAdapter中进行认证相关的配置，可以使用configure(AuthenticationManagerBuilder auth)暴露一个AuthenticationManager的建造器：AuthenticationManagerBuilder 。如上所示，我们便完成了内存中用户的配置。

细心的朋友会发现，在前面的文章中我们配置内存中的用户时，似乎不是这么配置的，而是：

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin").password("admin").roles("USER");
    }
}
```

如果你的应用只有唯一一个WebSecurityConfigurerAdapter，那么他们之间的差距可以被忽略，从方法名可以看出两者的区别：使用@Autowired注入的AuthenticationManagerBuilder是全局的身份认证器，作用域可以跨越多个WebSecurityConfigurerAdapter，以及影响到基于Method的安全控制；而 `protected configure()`的方式则类似于一个匿名内部类，它的作用域局限于一个WebSecurityConfigurerAdapter内部 .