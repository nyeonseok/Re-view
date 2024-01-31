package Login.demo;


import Login.demo.domain.UserRole;
import Login.demo.service.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final PrincipalOauth2UserService principalOauth2UserService;



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests()
//                .requestMatchers("/security-login/info").authenticated()
//                .requestMatchers("/security-login/admin/**").hasAuthority(UserRole.ADMIN.name())
                .requestMatchers("/info").authenticated()
                .requestMatchers("/admin/**").hasAuthority(UserRole.ADMIN.name())
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .usernameParameter("loginId")
                .passwordParameter("password")
//                .loginPage("/security-login/login")
//                .defaultSuccessUrl("/security-login")
                .loginPage("/login")
                .defaultSuccessUrl("/")
//                .failureUrl("/security-login/login")
                .failureUrl("/login")
                .and()
                .logout()
//                .logoutUrl("/security-login/logout")
                .logoutUrl("/logout")
                .invalidateHttpSession(true).deleteCookies("JSESSIONID")
                .and()
                .oauth2Login()
//                .loginPage("/security-login/login")
//                .defaultSuccessUrl("/security-login")
                .loginPage("/login")
                .defaultSuccessUrl("/")
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
        ;
        http
                .exceptionHandling()
                .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                .accessDeniedHandler(new MyAccessDeniedHandler());

        return http.build();
    }
}