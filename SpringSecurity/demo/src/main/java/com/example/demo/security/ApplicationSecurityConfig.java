package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.demo.security.ApplicationUserRole.*;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
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
                .formLogin()
                    .loginPage("/login")
                    .permitAll() // Login Page
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password") // Custom parameter name and name attribute must match in html
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // defaults to 2 weeks, but we changed to 21 days
                    .key("somethingVerySecured")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))// Only use when CSRF is Disabled
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder); // Allows password to be encoded
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}

/* In Memory Database Implementation
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
*/
