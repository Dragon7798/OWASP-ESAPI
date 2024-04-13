package com.esapiFilter.util;

import org.owasp.esapi.*;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.DB2Codec;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.*;

import javax.crypto.SecretKey;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ESAPIMethods {

    private static final Encoder encoder = ESAPI.encoder();
    private static final Validator validator = ESAPI.validator();
    private static final AccessController accessController = ESAPI.accessController();
    private static final Encryptor encryptor = ESAPI.encryptor();
    private static final Randomizer randomizer = ESAPI.randomizer();
    private static final HTTPUtilities httpUtilities = ESAPI.httpUtilities();


    private static final IntrusionDetector intrusion = ESAPI.intrusionDetector();

    private ESAPIMethods() {
    }

    public static String canonicalizeInput(String value, boolean flag) {
        return encoder.canonicalize(value, flag);
    }

    /**
     * Validator Methods
     **/
    public static boolean isValidInput(String context, String input, String type, int maxLength) {
        return validator.isValidInput(context, input, type, maxLength, true);
    }

    public static boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) {
        return validator.isValidInput(context, input, type, maxLength, allowNull);
    }

    public static boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) {
        return validator.isValidInput(context, input, type, maxLength, allowNull, errorList);
    }

    public static boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errorList) {
        return validator.isValidInput(context, input, type, maxLength, allowNull, canonicalize, errorList);
    }

    public static boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) {
        return validator.isValidInput(context, input, type, maxLength, allowNull, canonicalize);
    }

    public static int validateInteger(int value, int minValue, int maxValue, boolean allowNull) throws ValidationException {
        return validator.getValidInteger("validate Number", String.valueOf(value), minValue, maxValue, allowNull);
    }

    public static int validateInteger(String context, int value, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws ValidationException {
        return validator.getValidInteger(context, String.valueOf(value), minValue, maxValue, allowNull, errorList);
    }

    public static boolean isValidNumber(String context, String input, long minValue, long maxvalue, boolean allowNull) {
        return validator.isValidNumber(context, input, minValue, maxvalue, allowNull);
    }

    public static Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException {
        return validator.getValidNumber(context, input, minValue, maxValue, allowNull);
    }

    public static Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) {
        return validator.getValidNumber(context, input, minValue, maxValue, allowNull, errorList);
    }

    public static boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) {
        return validator.isValidDouble(context, input, minValue, maxValue, allowNull);
    }

    public static Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException {
        return validator.getValidDouble(context, input, minValue, maxValue, allowNull);
    }

    public static Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws ValidationException {
        return validator.getValidDouble(context, input, minValue, maxValue, allowNull, errorList);
    }

    public static boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) {
        return validator.isValidDouble(context, input, minValue, maxValue, allowNull, errorList);
    }

    public static Date validateDate(String value, DateFormat dateFormat, boolean allowNull) throws ValidationException {
        return validator.getValidDate("Validate Date", value, dateFormat, allowNull);
    }

    public static Date validateDate(String value, DateFormat dateFormat, boolean allowNull, ValidationErrorList errorList) throws ValidationException {
        return validator.getValidDate("Validate Date", value, dateFormat, allowNull, errorList);
    }

    public static boolean isValidDate(String context, String input, DateFormat dt, boolean allowNull) {
        return validator.isValidDate(context, input, dt, allowNull);
    }

    public static boolean isValidDate(String context, String input, DateFormat dt, boolean allowNull, ValidationErrorList errorList) {
        return validator.isValidDate(context, input, dt, allowNull, errorList);
    }

    public static String validateInput(String value, String type, int maxLength, boolean allowNull) throws ValidationException {
        return validator.getValidInput("Validate Input", value, type, maxLength, allowNull);
    }

    public static String validateInput(String value, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException {
        return validator.getValidInput("Validate Input", value, type, maxLength, allowNull, canonicalize);
    }

    public static String validateInput(String value, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws ValidationException {
        return validator.getValidInput("Validate Input", value, type, maxLength, allowNull, errorList);
    }

    public static String validateInput(String value, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errorList) {
        return validator.getValidInput("Validate Input", value, type, maxLength, allowNull, canonicalize, errorList);
    }

    public static boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) {
        return validator.isValidFileContent(context, input, maxBytes, allowNull);
    }

    public static boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) {
        return validator.isValidFileContent(context, input, maxBytes, allowNull, errorList);
    }

    public static byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) {
        return validator.getValidFileContent(context, input, maxBytes, allowNull, errorList);
    }

    public static byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException {
        return validator.getValidFileContent(context, input, maxBytes, allowNull);
    }

    public static boolean isValidFileUpload(String context, String directoryPath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull) {
        return validator.isValidFileUpload(context, directoryPath, filename, parent, content, maxBytes, allowNull);
    }

    public static boolean isValidFileUpload(String context, String directoryPath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errorList) {
        return validator.isValidFileUpload(context, directoryPath, filename, parent, content, maxBytes, allowNull, errorList);
    }

    public static boolean isValidListItem(String context, String input, List<String> list) {
        return validator.isValidListItem(context, input, list);
    }

    public static boolean isValidListItem(String context, String input, List<String> list, ValidationErrorList errorList) {
        return validator.isValidListItem(context, input, list, errorList);
    }

    public static String getValidListItem(String context, String input, List<String> list) throws ValidationException {
        return validator.getValidListItem(context, input, list);
    }

    public static String getValidListItem(String context, String input, List<String> list, ValidationErrorList errorList) {
        return validator.getValidListItem(context, input, list, errorList);
    }

    public static boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames) {
        return validator.isValidHTTPRequestParameterSet(context, request, requiredNames, optionalNames);
    }

    public static boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames, ValidationErrorList errorList) {
        return validator.isValidHTTPRequestParameterSet(context, request, requiredNames, optionalNames, errorList);
    }

    public static void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws ValidationException {
        validator.assertValidHTTPRequestParameterSet(context, request, required, optional);
    }

    public static void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) {
        validator.assertValidHTTPRequestParameterSet(context, request, required, optional, errorList);
    }

    public static boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull) {
        return validator.isValidPrintable(context, input, maxLength, allowNull);
    }

    public static boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) {
        return validator.isValidPrintable(context, input, maxLength, allowNull, errorList);
    }

    public static char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws ValidationException {
        return validator.getValidPrintable(context, input, maxLength, allowNull);
    }

    public static char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) {
        return validator.getValidPrintable(context, input, maxLength, allowNull, errorList);
    }

    public static String safeReadLine(InputStream inputStream, int max) throws ValidationException {
        return validator.safeReadLine(inputStream, max);
    }


    /**
     * Encoder Methods
     **/
    public static String encodeSQL(String query) {
        return encoder.encodeForSQL(new DB2Codec(), query);
    }

    public static String encodeBase64(String value) {
        return encoder.encodeForBase64(value.getBytes(), true);
    }

    public static byte[] decodeFromBase64(String value) throws IOException {
        return encoder.decodeFromBase64(value);
    }

    public static String encodeForJS(String value) {
        return encoder.encodeForJavaScript(value);
    }

    public static String encodeForHTML(String value) {
        return encoder.encodeForHTML(value);
    }

    public static String decodeForHTML(String value) {
        return encoder.decodeForHTML(value);
    }

    public static String encodeForCSS(String value) {
        return encoder.encodeForCSS(value);
    }

    public static String encodeForHtmlAttribute(String value) {
        return encoder.encodeForHTMLAttribute(value);
    }

    public static String encodeForXml(String value) {
        return encoder.encodeForXML(value);
    }

    public static String encodeForUrl(String value) throws EncodingException {
        return encoder.encodeForURL(value);
    }

    public static String decodeFromUrl(String value) throws EncodingException {
        return encoder.decodeFromURL(value);
    }

    public static String encodeForVBScript(String value) {
        return encoder.encodeForVBScript(value);
    }

    /**
     * Encode for an operating system command shel
     */
    public static String encodeForOs(Codec codec, String value) {
        return encoder.encodeForOS(codec, value);
    }

    /**
     * LDAP stands for Lightweight Directory Access Protocol. LDAP queries are used to search for and retrieve information, LDAP queries are used to search for specific directory entries based on attributes such as name, email address, group membership, organizational unit, or any other attribute defined in the directory schema.
     **/
    public static String encodeForLDAP(String value) {
        return encoder.encodeForLDAP(value);
    }

    public static String encodeForXPath(String value) {
        return encoder.encodeForXPath(value);
    }


    /**
     * Encryptor Methods
     **/
    public static String hash(String plainText, String salt) throws EncryptionException {
        return encryptor.hash(plainText, salt);
    }

    public static String hash(String plainText, String salt, int iterations) throws EncryptionException {
        return encryptor.hash(plainText, salt, iterations);
    }

    public static CipherText encryptData(PlainText plainText) throws EncryptionException {
        return encryptor.encrypt(plainText);
    }

    public static CipherText encryptData(PlainText plainText, SecretKey skey) throws EncryptionException {
        return encryptor.encrypt(skey, plainText);
    }

    public static PlainText decryptData(CipherText cipherText) throws EncryptionException {
        return encryptor.decrypt(cipherText);
    }

    public static PlainText decryptData(CipherText cipherText, SecretKey skey) throws EncryptionException {
        return encryptor.decrypt(skey, cipherText);
    }

    public static String signature(String value) throws EncryptionException {
        return encryptor.sign(value);
    }


    public static String seal(String data, long expirationTime) throws IntegrityException {
        return encryptor.seal(data, expirationTime);
    }

    public static String seal(String seal) throws IntegrityException, EncryptionException {
        return encryptor.unseal(seal);
    }

    public static boolean verifySeal(String seal) {
        return encryptor.verifySeal(seal);
    }

    /**
     * Intrusion Methods
     **/
    public static void addIntrusionException(Exception exception) {
        intrusion.addException(exception);
    }

    public static void addIntrusionEvent(String event, String logMessage) {
        intrusion.addEvent(event, logMessage);
    }

    /**
     * Access Controller Methods
     **/

    public static boolean isAuthorized(Object key, Object param) {

        return accessController.isAuthorized(key, param);
    }

    public static void assertAuthorized(Object key, Object param) throws AccessControlException {
        accessController.assertAuthorized(key, param);
    }

    public static void assertAuthorizedForData(String action, Object data) throws AccessControlException {
        accessController.assertAuthorizedForData(action, data);
    }

    public static void assertAuthorizedForFile(String filePath) throws AccessControlException {
        accessController.assertAuthorizedForFile(filePath);
    }

    public static void assertAuthorizedForFunction(String functionName) throws AccessControlException {
        accessController.assertAuthorizedForFile(functionName);
    }

    public static void assertAuthorizedForService(String serviceName) throws AccessControlException {
        accessController.assertAuthorizedForService(serviceName);
    }

    public static void assertAuthorizedForUrl(String url) throws AccessControlException {
        accessController.assertAuthorizedForURL(url);
    }

    public static boolean isAuthorizedForData(String action, Object data) {
        return accessController.isAuthorizedForData(action, data);
    }

    public static boolean isAuthorizedForFile(String filepath) {
        return accessController.isAuthorizedForFile(filepath);
    }

    public static boolean isAuthorizedForFunction(String functionName) {
        return accessController.isAuthorizedForFunction(functionName);
    }

    public static boolean isAuthorizedForService(String serviceName) {
        return accessController.isAuthorizedForService(serviceName);
    }

    public static boolean isAuthorizedForUrl(String url) {
        return accessController.isAuthorizedForURL(url);
    }

    public static boolean getRandomBoolean() {
        return randomizer.getRandomBoolean();
    }

    public static String getRandomFilename(String extension) {
        return randomizer.getRandomFilename(extension);
    }

    public static long getRandomLong() {
        return randomizer.getRandomLong();
    }

    public static int getRandomInteger(int min, int max) {
        return randomizer.getRandomInteger(min, max);
    }

    public static String getRandomString(int length, char[] chars) {
        return randomizer.getRandomString(length, chars);
    }

    public static float getRandomString(float min, float max) {
        return randomizer.getRandomReal(min, max);
    }

    public static void addCookie(Cookie cookie) {
        httpUtilities.addCookie(cookie);
    }

    public static void addCookie(HttpServletResponse response, Cookie cookie) {
        httpUtilities.addCookie(response, cookie);
    }

    public static String addCSRFToken(String href) {
        return httpUtilities.addCSRFToken(href);
    }

    public static void addHeader(String name, String value) {
        httpUtilities.addHeader(name, value);
    }

    public static void addHeader(HttpServletResponse response, String name, String value) {
        httpUtilities.addHeader(response, name, value);
    }

    public static String decryptHiddenField(String encryptedValue) {
        return httpUtilities.decryptHiddenField(encryptedValue);
    }

    public static Map<String, String> decryptQueryString(String queryString) throws EncryptionException {
        return httpUtilities.decryptQueryString(queryString);
    }

    public static Map<String, String> decryptStateFromCookie(HttpServletRequest request) throws EncryptionException {
        return httpUtilities.decryptStateFromCookie(request);
    }

    public static Map<String, String> decryptStateFromCookie() throws EncryptionException {
        return httpUtilities.decryptStateFromCookie();
    }

    public static String encryptHiddenField(String value) throws EncryptionException {
        return httpUtilities.encryptHiddenField(value);
    }

    public static String encryptQueryString(String query) throws EncryptionException {
        return httpUtilities.encryptQueryString(query);
    }

    public static void encryptStateInCookie(Map<String, String> clearText) throws EncryptionException {
        httpUtilities.encryptStateInCookie(clearText);
    }

    public static void encryptStateInCookie(HttpServletResponse response, Map<String, String> clearText) throws EncryptionException {
        httpUtilities.encryptStateInCookie(response, clearText);
    }

    public static String getCookie(String name) throws ValidationException {
        return httpUtilities.getCookie(name);
    }

    public static String getCookie(HttpServletRequest request, String name) throws ValidationException {
        return httpUtilities.getCookie(request, name);
    }

    public static String getCSRFToken() {
        return httpUtilities.getCSRFToken();
    }

    public static HttpServletRequest getCurrentRequest() {
        return httpUtilities.getCurrentRequest();
    }

    public static HttpServletResponse getCurrentResponse() {
        return httpUtilities.getCurrentResponse();
    }

    public static List getFileUploads() throws ValidationException {
        return httpUtilities.getFileUploads();
    }

    public static List getFileUploads(HttpServletRequest request) throws ValidationException {
        return httpUtilities.getFileUploads(request);
    }

    public static List getFileUploads(HttpServletRequest request, File finalDir) throws ValidationException {
        return httpUtilities.getFileUploads(request, finalDir);
    }

    public static List getFileUploads(HttpServletRequest request, File finalDir, List allowedExtensions) throws ValidationException {
        return httpUtilities.getFileUploads(request, finalDir, allowedExtensions);
    }


    public static String getFileUploads(String name) throws ValidationException {
        return httpUtilities.getHeader(name);
    }

    public static String getFileUploads(HttpServletRequest request, String name) throws ValidationException {
        return httpUtilities.getHeader(request, name);
    }

    public static String getParameter(HttpServletRequest request, String name) throws ValidationException {
        return httpUtilities.getParameter(request, name);
    }

    public static String getParameter(String name) throws ValidationException {
        return httpUtilities.getParameter(name);
    }

    public static String getRequestAttribute(String key) {
        return httpUtilities.getRequestAttribute(key);
    }

    public static String getRequestAttribute(HttpServletRequest request, String key) {
        return httpUtilities.getRequestAttribute(request, key);
    }

    public static String getSessionAttribute(String key) {
        return httpUtilities.getSessionAttribute(key);
    }

    public static String getSessionAttribute(HttpSession session, String key) {
        return httpUtilities.getSessionAttribute(session, key);
    }

    public static void killAllCookies() {
        httpUtilities.killAllCookies();
    }

    public static void killAllCookies(HttpServletRequest request, HttpServletResponse response) {
        httpUtilities.killAllCookies(request, response);
    }

    public static void killAllCookies(HttpServletRequest request, HttpServletResponse response, String name) {
        httpUtilities.killCookie(request, response, name);
    }

    public static void killAllCookies(String name) {
        httpUtilities.killCookie(name);
    }

    public static void sendForward(HttpServletRequest request, HttpServletResponse response, String location) throws ServletException, AccessControlException, IOException {
        httpUtilities.sendForward(request, response, location);
    }


    public static void sendForward(String location) throws ServletException, AccessControlException, IOException {
        httpUtilities.sendForward(location);
    }

    public static void sendRedirect(String location) throws AccessControlException, IOException {
        httpUtilities.sendRedirect(location);
    }

    public static void sendRedirect(HttpServletResponse response, String location) throws AccessControlException, IOException {
        httpUtilities.sendRedirect(response, location);
    }

    public static void setContentType() {
        httpUtilities.setContentType();
    }

    public static void setContentType(HttpServletResponse response) {
        httpUtilities.setContentType(response);
    }

    public static void setContentType(HttpServletRequest request, HttpServletResponse response) {
        httpUtilities.setCurrentHTTP(request, response);
    }

    public static void setHeader(String name, String value) {
        httpUtilities.setHeader(name, value);
    }

    public static void setHeader(HttpServletResponse response, String name, String value) {
        httpUtilities.setHeader(response, name, value);
    }

    public static void setNoCacheHeaders() {
        httpUtilities.setNoCacheHeaders();
    }

    public static void setNoCacheHeaders(HttpServletResponse response) {
        httpUtilities.setNoCacheHeaders(response);
    }

    public static String setRememberToken(String password, int maxAge, String domain, String path) {
        return httpUtilities.setRememberToken(password, maxAge, domain, path);
    }

    public static String setNoCacheHeaders(HttpServletRequest request, HttpServletResponse response, String password, int maxAge, String domain, String path) {
        return httpUtilities.setRememberToken(request, response, password, maxAge, domain, path);
    }

    public static void verifyCSRFToken() {
        httpUtilities.verifyCSRFToken();
    }

    public static void verifyCSRFToken(HttpServletRequest request) {
        httpUtilities.verifyCSRFToken(request);
    }
}
