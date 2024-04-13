package com.esapiFilter.filters;

import com.shaft.framework.exceptions.ServiceException;
import org.osgi.service.component.annotations.Component;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.ValidationException;

import javax.servlet.*;
import java.io.IOException;


@Component(service = {Filter.class}, property = {"service.description=verify the request and sanitize the inputs", "sling.filter.scope=REQUEST", "sling.filter.pattern=/shaft/api/esapi-servlet", "service.ranking:Integer=-399"})
public class ESAPIFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            chain.doFilter(new SanitizedRequestClass(request), response);
        } catch (ValidationException | AuthenticationException e) {
            throw new ServiceException(e.getMessage(), -1, false);
        }
    }

    @Override
    public void destroy() {

    }

}
