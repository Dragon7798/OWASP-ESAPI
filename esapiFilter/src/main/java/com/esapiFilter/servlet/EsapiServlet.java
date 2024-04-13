package com.esapiFilter.servlet;

import com.google.gson.JsonObject;
import com.shaft.framework.commons.JsonUtil;
import com.shaft.framework.servlets.ShaftAllMethodsServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component(service = Servlet.class, property = {
        Constants.SERVICE_DESCRIPTION + "=ESAPI Filter",
        "sling.servlet.methods" + "=" + HttpConstants.METHOD_POST,
        "sling.servlet.resourceTypes" + "=/apps/shaft/esapi/filter"})
public class EsapiServlet extends ShaftAllMethodsServlet {
    private static final JsonUtil jsonUtil = JsonUtil.getInstance();

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) throws ServletException, IOException {
        response.setContentType("application/json");
        String requestStr = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        JsonObject reqObj = jsonUtil.parseJson.apply(requestStr).getAsJsonObject();
        JsonObject bodyjson = jsonUtil.getIfJsonObject.apply(reqObj.get("body")).getAsJsonObject();
        String value = "";

        Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
        value = scriptPattern.matcher(value).replaceAll("");

//            int z = ESAPI.validator().getValidInteger("Demo", response2, 20, 100, true);

        response.getWriter().println(bodyjson.toString());

    }
}