package com.ruoyi.framework.security.filter;

import java.io.IOException;
import java.util.Enumeration;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.web.service.TokenService;

/**
 * token过滤器 验证token有效性
 * 
 * @author ruoyi
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter
{
    @Autowired
    private TokenService tokenService;



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException
    {
        System.out.println("进入鉴权 每一个请求都会经过这一步 因为这是一个Filter 这一步的目的是从request获取tonken 如果有就会从hearder取token-->解密token-->从redis中获取对应的用户信息。保存到上下文 后续filter会读取上下文判断是否认证失败 有上下文认证成功就走成功路径 失败就走失败路径 走到权限认证失败处理类");
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (StringUtils.isNotNull(loginUser) && StringUtils.isNull(SecurityUtils.getAuthentication()))
        {
            System.out.println("请求中带有token信息并且token能在redis查到对应用户");
            //判断token时间 刷新redis中的token 把loginusr存到redis
            //1. redis保存的key为login_tokens:+UUID 例如:login_tokens:c449f8db-ac5d-4f52-a966-ccb06822d274   -hwb
            System.out.println("刷新已存在redis中的token时间");
            tokenService.verifyToken(loginUser);
            System.out.println("把该请求的token鉴权设置到Spring Security上下文中 用于后续逻辑的调用运行");
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }else {
            System.out.println("requst有错误token或者没有token 总之redis匹配不到登录用户 就不做处理 不用赋予鉴权上下文");
        }

        //到达后一个filter
        chain.doFilter(request, response);
        System.out.println("这是dofilter做完之后发出的消息");
    }

}
