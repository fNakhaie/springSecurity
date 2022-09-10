package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // aware spring that we use @PreAuthorize in rest controller

public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    @Autowired
    public WebSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    private  static final String MANAGEMENT_API = "/management/api/**";
    private  static final String PASSWORD = "password";
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
//                if we have to call api from ui to prevent forgery
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
//                if we don't want to use @PreAuthorize then should use these lines
//                .antMatchers(HttpMethod.DELETE,MANAGEMENT_API).hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,MANAGEMENT_API).hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,MANAGEMENT_API).hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(MANAGEMENT_API).hasAnyRole(ADMIN.name(),ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user1 = User.builder()
                .username("user1")
                .password(passwordEncoder.encode(PASSWORD))
                .authorities(STUDENT.getGrantedAuthority())
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode(PASSWORD))
                .authorities(ADMIN.getGrantedAuthority())
                .build();

        UserDetails adminTrainee = User.builder()
                .username("adminTrainee")
                .password(passwordEncoder.encode(PASSWORD))
                .authorities(ADMIN_TRAINEE.getGrantedAuthority())
                .build();
        return new InMemoryUserDetailsManager(user1,admin,adminTrainee);
    }
}