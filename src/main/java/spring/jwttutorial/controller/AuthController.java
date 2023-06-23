package spring.jwttutorial.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.jwttutorial.dto.LoginDto;
import spring.jwttutorial.dto.TokenDto;
import spring.jwttutorial.jwt.JwtFilter;
import spring.jwttutorial.jwt.TokenProvider;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    /**
     * 로그인 API
     */
    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        //UsernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //authenticationToken을 이용해서 Authentication 객체를 생성하려고 authenticate()메서드가 실행이 될 때 loadUserByUsername 메서드가 실행된다. -> loadUserByUsername 메서드의 결과값으로 인증된 사용자 정보를 가진 UserDetails가 반환 -> 이걸 가지고 Authentication 생성
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);       //SecuritContext에 authentication 저장

        String jwt = tokenProvider.createToken(authentication); //jwt 생성

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);           //JWT Token을 Response Header에도 넣어주고,

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);            //TokenDto를 이용해서 Response Body에도 넣어서 리턴
    }

}
