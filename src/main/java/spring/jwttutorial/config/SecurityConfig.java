package spring.jwttutorial.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {




    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable
                // 이 설정으로 h2-console에서 connect이후 화면을 보여주기 위함도 있음.
                .csrf().disable()

                //h2-console 하위 모든 요청들과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않도록 설정
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .authorizeHttpRequests()//HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다는 의미
                .requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()//해당 요청은 인증없이 접근 허용
                .requestMatchers(PathRequest.toH2Console()).permitAll()
                .anyRequest().authenticated();//나머지 요청은 인증 필요


        return httpSecurity.build();
    }
}
