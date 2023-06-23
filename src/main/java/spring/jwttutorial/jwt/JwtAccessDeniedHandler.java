package spring.jwttutorial.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * JwtAccessDeniedHandler: 필요한 권한이 존재하지 않는 경우에 403 Forbidden 에러를 리턴하는 역할
 */
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    // handle 메서드: 인증은 되었지만 권한 없이 접근하였을 때 발생하는 메서드
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        //필요한 권한이 없이 접근하려 할때 403
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

}
