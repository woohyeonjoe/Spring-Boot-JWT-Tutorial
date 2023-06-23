package spring.jwttutorial.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;


/**
 * TokenProvider: 토큰의 생성, 토큰의 유효성 검증 등을 담당
 */
@Component
public class TokenProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long tokenValidityInMilliseconds;
    private Key key;


    // 빈이 생성되고 의존성 주입을 받은 후에 secret 값을 afterPropertiesSet() 메서드에서 Base64 Decode 해서 key 변수에 할당
    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    // 빈이 초기화된 후 추가 작업을 수행하는 메서드
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }


    // Authentication 객체의 권한정보를 담은 토큰을 생성하는 createToken() 메서드
    public String createToken(Authentication authentication) {
        //Authentication 객체의 권한정보
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // yml 파일에 설정했던 만료시간을 설정하고 토큰 생성
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds);

        // 토큰 생성해서 리턴
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }


    // Token에 담겨있는 권한 정보를 이용해 Authentication 객체를 리턴하는 getAuthentication() 메서드
    public Authentication getAuthentication(String token) {
        // 토큰으로 클레임을 만들고 이를 이용해 유저 객체를 만들어서 최종적으로 Authentication 객체를 리턴

        // 클레임: JWT의 페이로드 부분에 포함되는 정보, 클레임은 토큰을 검증하고 정보를 사용자에게 전달하는데 사용
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        //클레임에서 권한정보(authorities)를 조회
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        //권한정보(authorities)로 User객체 생성 -> 이 때 User는 SpringSecurity에서 제공하는 User이다.
        User principal = new User(claims.getSubject(), "", authorities);

        //User 정보, 토큰, 권한정보로 Authentication 객체를 생성해서 리턴
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }


    // 토큰의 유효성 검증을 수행하는 validateToken() 메서드
    public boolean validateToken(String token) {
        // 토큰을 파싱해보고 발생하는 익셉션들을 캐치, 문제가 있으면 false, 정상이면 true
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}
