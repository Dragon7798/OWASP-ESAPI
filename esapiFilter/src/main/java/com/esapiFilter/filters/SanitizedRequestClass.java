package com.esapiFilter.filters;

import com.esapiFilter.util.ESAPIMethods;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.shaft.framework.commons.JsonUtil;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultUser;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;
/**
 * The SanitizedRequestClass is a wrapper class for HttpServletRequest that sanitizes incoming request data to prevent
 * cross-site scripting (XSS) and SQL injection attacks. It uses the ESAPI library to perform input validation and
 * canonicalization, and encodes user input to prevent malicious code injection. The sanitized request data is then
 * passed on to the original request object for processing.
 */

public class SanitizedRequestClass extends HttpServletRequestWrapper {
    /**
     * The JsonUtil instance for parsing and manipulating JSON data.
     */
    private static final JsonUtil jsonUtil = JsonUtil.getInstance();

    /**
     * The raw request data as a byte array.
     */
    private final byte[] rawData;

    /**
     * Constructs a SanitizedRequestClass object that wraps the given HttpServletRequest object and sanitizes its data.
     *
     * @param request the original HttpServletRequest object to be wrapped
     * @throws IOException if an I/O error occurs while reading the request data
     * @throws ValidationException if input validation fails
     * @throws AuthenticationException if authentication fails
     */
    public SanitizedRequestClass(HttpServletRequest request) throws IOException, ValidationException, AuthenticationException {
        super(request);
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                char[] charBuffer = new char[
                        128
                        ];
                int bytesRead;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer,
                            0, bytesRead);
                }
            } else {
                // handle empty request body
            }
        } catch (IOException var14) {
            throw var14;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException var13) {
                    throw var13;
                }
            }
        }
        String sanitizedString = this.sanitizeData(stringBuilder.toString(), request);
        this.rawData = sanitizedString.getBytes();
    }
    /**
     * Constructs a SanitizedRequestClass object that wraps the given ServletRequest object and sanitizes its data.
     *
     * @param request the original ServletRequest object to be wrapped
     * @throws IOException if an I/O error occurs while reading the request data
     * @throws ValidationException if input validation fails
     * @throws AuthenticationException if authentication fails
     */
    public SanitizedRequestClass(ServletRequest request) throws IOException, ValidationException, AuthenticationException {
        this((HttpServletRequest) request);
    }
    /**
     * Sanitizes the request data by performing input validation, canonicalization, and encoding to prevent XSS and SQL
     * injection attacks.
     *
     * @param body the request body as a string
     * @param request the original HttpServletRequest object
     * @return the sanitized request data as a string
     * @throws ValidationException if input validation fails
     * @throws AuthenticationException if authentication fails
     */
    private String sanitizeData(String body, HttpServletRequest request) throws ValidationException, AuthenticationException {
        String contentType = request.getContentType();
        User user = new DefaultUser("admin");
        ESAPI.authenticator().setCurrentUser(user);
        Set role = new HashSet();
        role.add("user");
        user.setRoles(role);
        String a = "<script>adda</script>";
        Exception exception = new Exception("Failed");
        ESAPI.intrusionDetector().addException(exception);
        ESAPI.intrusionDetector().addEvent("IntrusionEvent",
                "Intrusion detected for string" + a);
        boolean res = ESAPI.accessController().isAuthorizedForService("/shaft-crfs-filter");
        if (contentType.equalsIgnoreCase("application/json")) {
            JsonObject reqObj = jsonUtil.parseJson.apply(body).getAsJsonObject();
            JsonObject bodyJson = jsonUtil.getIfJsonObject.apply(reqObj.get("body")).getAsJsonObject();
            Set<String> keys = bodyJson.keySet();
            for (String key : keys) {
                JsonElement value = bodyJson.get(key);
                if (value.isJsonPrimitive()) {
                    String sanitizedValue = ESAPIMethods.canonicalizeInput(value.getAsString(), true);
                    sanitizedValue = String.valueOf(ESAPIMethods.validateInteger(Integer.parseInt(sanitizedValue),
                            10,
                            150, true));
                    bodyJson.addProperty(key, sanitizedValue);
                } else if (value.isJsonObject()) {
                    JsonObject innerObject = new JsonObject();
                    value.getAsJsonObject().entrySet().forEach(entry -> {
                        String sanitizedValue = ESAPIMethods.canonicalizeInput(entry.getValue().getAsString(), true);
                        sanitizedValue = ESAPIMethods.encodeForHTML(sanitizedValue);
                        innerObject.addProperty(entry.getKey(), sanitizedValue);
                    });
                    bodyJson.add(key, innerObject);
                } else if (value.isJsonArray()) {
                    JsonArray emptyArray = new JsonArray();
                    value.getAsJsonArray().forEach(jsonElement -> {
                        String sanitizedValue = ESAPIMethods.canonicalizeInput(jsonElement.getAsString(), true);
                        sanitizedValue = ESAPIMethods.encodeSQL(sanitizedValue);
                        emptyArray.add(sanitizedValue);
                    });
                    bodyJson.add(key, emptyArray);
                }
            }
            reqObj.add("body", bodyJson);
            return reqObj.toString();
        } else {
            return body;
        }
    }
    /**
     * Returns a ServletInputStream object that reads the sanitized request data.
     *
     * @return a ServletInputStream object that reads the sanitized request data
     */
    public ServletInputStream getInputStream() {
        return new ServletInputStream() {
            byte[] myBytes;
            private int lastIndexRetrieved;
            private int readLimit;
            private int markedPosition;
            private ReadListener readListener;
            {
                this.myBytes = SanitizedRequestClass.this.rawData;
                this.lastIndexRetrieved = -1;
                this.readLimit = -1;
                this.markedPosition = -1;
                this.readListener = null;
            }
            public int read() throws IOException {
                if (!this.isFinished()) {
                    int i = this.myBytes[this.lastIndexRetrieved + 1
                            ];
                    ++this.lastIndexRetrieved;
                    if (this.isFinished() && this.readListener != null) {
                        try {
                            this.readListener.onAllDataRead();
                        } catch (IOException var3) {
                            this.readListener.onError(var3);
                            throw var3;
                        }
                        this.readLimit = -1;
                    }
                    if (this.readLimit != -1 && this.lastIndexRetrieved - this.markedPosition > this.readLimit) {
                        this.markedPosition = -1;
                        this.readLimit = -1;
                    }
                    return i;
                } else {
                    return -1;
                }
            }
            public boolean markSupported() {
                return true;
            }
            public synchronized void mark(int readLimit) {
                this.readLimit = readLimit;
                this.markedPosition = this.lastIndexRetrieved;
            }
            public synchronized void reset() throws IOException {
                if (this.markedPosition == -1) {
                    throw new IOException("No mark found");
                } else {
                    this.lastIndexRetrieved = this.markedPosition;
                    this.readLimit = -1;
                }
            }
            public boolean isFinished() {
                return this.lastIndexRetrieved == this.myBytes.length - 1;
            }
            public boolean isReady() {
                return this.isFinished();
            }
            public void setReadListener(ReadListener readListener) {
                this.readListener = readListener;
                if (!this.isFinished()) {
                    try {
                        readListener.onDataAvailable();
                    } catch (IOException var4) {
                        readListener.onError(var4);
                    }
                } else {
                    try {
                        readListener.onAllDataRead();
                    } catch (IOException var3) {
                        readListener.onError(var3);
                    }
                }
            }
            public int available() throws IOException {
                return this.myBytes.length - this.lastIndexRetrieved - 1;
            }
            public void close() throws IOException {
                this.lastIndexRetrieved = this.myBytes.length - 1;
                this.myBytes = null;
            }
        };
    }
}