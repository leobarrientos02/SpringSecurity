package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;

import static com.example.demo.security.ApplicationUserRole.*;
import static com.example.demo.security.ApplicationUserPermission.*;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
/*              This is used when data is being passed through the browser but not needed for practice
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
 */
                .csrf().disable() // This is to disable the csrf but not recommended
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll() // anyMatchers and permitAll are used to allow pages with no authorization
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
//                .httpBasic();  Basic Authentication
                .formLogin();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
      UserDetails leoBarrientosUser = User.builder()
                .username("leoBarrientos")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

      UserDetails joseUser = User.builder()
              .username("joseBarrientos")
              .password(passwordEncoder.encode("password"))
//              .roles(ADMIN.name())
              .authorities(ADMIN.getGrantedAuthorities())
              .build();

      UserDetails mynorUser = User.builder()
              .username("mynorPimentel")
              .password(passwordEncoder.encode("password"))
//              .roles(ADMINTRAINEE.name())
              .authorities(ADMINTRAINEE.getGrantedAuthorities())
              .build();

      return new InMemoryUserDetailsManager(leoBarrientosUser, joseUser, mynorUser );
    }
}
