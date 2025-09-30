package token_tailor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JOptionPane;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;

/**
 * CustomHttpHandler - Handles HTTP traffic interception for Token Tailor.
 *
 * This class intercepts all HTTP requests and responses from Burp Suite tools.
 * It performs the following key functions:
 *
 * 1. Request Interception: Automatically injects fresh tokens into outgoing requests
 * 2. Response Monitoring: Detects expired token conditions in responses
 * 3. Token Refresh: Executes the configured token acquisition workflow when tokens expire
 * 4. Automatic Retry: Retries failed requests with fresh tokens
 *
 * The handler maintains session state including the current token headers and tracks
 * whether a token was just refreshed to avoid infinite refresh loops.
 *
 * @author br1
 */
public class CustomHttpHandler implements HttpHandler {
        // Core components
        Logging logging;
        MontoyaApi montoyaApi;

        // Configuration from persistent storage
        PersistedList<HttpRequestResponse> req_res;          // Token acquisition workflow steps
        PersistedList<HttpResponse> expired_conditions;      // Patterns indicating expired tokens
        PersistedList<Boolean> active_state;                 // Whether extension is active
        PersistedList<Boolean> tools_check;                  // Which Burp tools to monitor
        PersistedList<Boolean> http_check;                   // HTTP/HTTPS settings

        // Runtime state
        ArrayList<HttpHeader> session;                       // Current token headers to inject
        Map<Instant, HttpResponse> tokenHistory = new HashMap<>();  // History of token responses
        Boolean isTokenNew = false;                          // Flag to prevent infinite token refresh loops

        // Regular expressions for token detection
        private Pattern jwtPattern = Pattern.compile("\\b(eyJ[A-Za-z0-9-_]+)\\.(eyJ[A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\b", Pattern.CASE_INSENSITIVE);
        private Pattern basicAuthPattern = Pattern.compile("[A-Za-z0-9+/]{6,}={0,}", Pattern.CASE_INSENSITIVE);
        private Pattern basic2Pattern = Pattern.compile("^[^:]+:[^:]+$", Pattern.CASE_INSENSITIVE);

        /**
         * Constructor for CustomHttpHandler.
         *
         * @param montoyaApi Burp Suite API for making HTTP requests and utilities
         * @param logging Logger for extension messages
         * @param req_res Token acquisition workflow configuration
         * @param expired_conditions Response patterns that indicate expired tokens
         * @param active_state Extension activation state
         * @param tools_check Which Burp tools are monitored
         * @param http_check HTTP/HTTPS settings for each request
         */
        public CustomHttpHandler(MontoyaApi montoyaApi, Logging logging, PersistedList<HttpRequestResponse> req_res, PersistedList<HttpResponse> expired_conditions, PersistedList<Boolean> active_state , PersistedList<Boolean> tools_check, PersistedList<Boolean> http_check ) {

                this.logging = logging;
                this.montoyaApi = montoyaApi;

                this.req_res = req_res;
                this.expired_conditions = expired_conditions;
                this.active_state = active_state;
                this.tools_check = tools_check;
                this.http_check = http_check;
        }

        /**
         * Extracts all JWT tokens from a text string.
         *
         * @param text The text to search for JWT tokens
         * @return A list of JWT tokens found in the text
         */
        private List<String> extractJwts(String text) {
                List<String> jwts = new ArrayList<>();
                Matcher matcher = jwtPattern.matcher(text);

                while (matcher.find()) {
                        jwts.add(matcher.group());
                }

                return jwts;
        }

        /**
         * Checks if a string is a valid JWT token.
         * Verifies the token has exactly three dot-separated parts.
         *
         * @param value The string to check
         * @return true if the value is a JWT token, false otherwise
         */
        private boolean isJWT(String value) {

                Matcher matcher = jwtPattern.matcher(value);

                while (matcher.find()) {
                        String[] parts = matcher.group(0).split("\\.");
                        if (parts.length == 3) {
                                return true;
                        } else{
                                return false;
                        }
                }
                return false;
        }

        /**
         * Checks if a string is a valid Basic Authentication token.
         * Decodes the Base64 string and verifies it matches the "username:password" format.
         *
         * @param input The Base64-encoded string to check
         * @return true if the value is valid Basic Auth, false otherwise
         */
        private boolean isBasicAuth(String input) {
                try {
                    // Use Montoya's Base64 utils to decode
                    ByteArray decodedBytes = montoyaApi.utilities().base64Utils().decode(input);
                    String decodedString = decodedBytes.toString();

                    // Check if the decoded string matches the "username:password" format
                    Matcher matcher = basic2Pattern.matcher(decodedString);

                    return matcher.matches();
                } catch (Exception e) {
                    // Handle any decoding errors (Montoya may throw its own exceptions)
                    return false;
                }
            }

        /**
         * Extracts all Basic Authentication tokens from a text string.
         *
         * @param text The text to search for Basic Auth tokens
         * @return A list of Base64-encoded Basic Auth tokens found in the text
         */
        private List<String> extractBasicAuth(String text) {
                List<String> basics = new ArrayList<>();
                Matcher matcher = basicAuthPattern.matcher(text);
        
                while (matcher.find()) {
                        basics.add(matcher.group());
                }
                
                return basics;
        }

        /**
         * Modifies an HTTP request by adding or updating headers.
         * Handles special cases for Authorization and Cookie headers.
         *
         * For Authorization headers:
         * - Adds "Bearer " prefix for JWT tokens
         * - Adds "Basic " prefix for Basic Auth tokens
         *
         * For Cookie headers:
         * - Merges new cookies with existing ones
         * - Updates existing cookie values if names match
         *
         * @param request The original HTTP request
         * @param headers The headers to add or update
         * @return The modified HTTP request
         */
        private HttpRequest editRequest (HttpRequest request, ArrayList<HttpHeader> headers) {

                for (HttpHeader ah : headers){
                        if(request.hasHeader(ah.name())){
                                if(ah.name().equals("Authorization")){

                                        String str = (isJWT(ah.value()) ? "Bearer " : "Basic ") + ah.value();;
                                        request = request.withUpdatedHeader(ah.name(), str);
                                
                                } else if (ah.name().equals("Cookie")){
                                        
                                        ArrayList<String> cookies = new ArrayList<>(Arrays.asList(request.header("Cookie").value().trim().split(";")));
                                        
                                        ArrayList<String> cookiesName = new ArrayList<>();
                                        ArrayList<String> cookiesValue = new ArrayList<>();
                                        for(String c : cookies){
                                                cookiesName.add(c.split("=")[0].trim());
                                                if (c.split("=").length > 1)
                                                        cookiesValue.add(c.split("=")[1]);
                                                else {
                                                        cookiesValue.add("");
                                                }
                                        }

                                        String cookieToAdd = ah.value().split(";")[0];
                                        String cookieToAddName = cookieToAdd.split("=")[0];
                                        String cookieToAddValue = "";
                                        if (cookieToAdd.split("=").length > 1)
                                                cookieToAddValue = cookieToAdd.split("=")[1];

                                        boolean changed = false;
                                        for(int i=0; i<cookiesName.size();i++){
                                                if (cookiesName.get(i).equals(cookieToAddName)){
                                                        cookiesValue.set(i, cookieToAddValue);
                                                        changed = true;
                                                }
                                        }
                                        String oneCookie = "";
                                        if(changed){
                                                for(int j=0; j<cookiesName.size();j++){
                                                        oneCookie = oneCookie + cookiesName.get(j).trim()+ "="+ cookiesValue.get(j) + "; ";
                                                }
                                        } else {
                                                for(String c : cookies){
                                                        oneCookie = oneCookie + c.trim() + "; ";
                                                }
                                                oneCookie = oneCookie + cookieToAdd + ";"; 
                                        }
                                                                                
                                        request = request.withUpdatedHeader(ah.name(), oneCookie);

                                } else{
                                        request = request.withUpdatedHeader(ah);
                                }
                        } else {
                                if(ah.name().equals("Authorization")){
                                        String str = (isJWT(ah.value()) ? "Bearer " : "Basic ") + ah.value();;
                                        
                                        request = request.withAddedHeader(ah.name(), str);
                                        
                                }else if (ah.name().equals("Cookie")){
                                        request = request.withAddedHeader(ah.name(), ah.value().split(";")[0]+";");
                                } else {
                                        request = request.withAddedHeader(ah);
                                }
                        }
                }

                return request;
        }

        /**
         * Extracts authentication headers from an HTTP response.
         * Compares the actual response with the saved/configured response to extract tokens.
         *
         * The method handles two scenarios:
         * 1. If the saved response contains § markers, only extract values within markers
         * 2. If no markers, extract all JWT/Basic Auth tokens from the response
         *
         * Extracted tokens are converted to Authorization or Cookie headers for injection
         * into subsequent requests.
         *
         * @param response The actual HTTP response received
         * @param saved The saved/configured response template with optional § markers
         * @return List of headers to inject, or null if extraction fails
         */
        private ArrayList<HttpHeader> takeSession(HttpResponse response, HttpResponse saved){

                ArrayList<HttpHeader> headers = new ArrayList<>();
                
                // If the saved response contains '§', extract only the portion defined by the user.
                if(saved.toString().contains("§")) {
                        //cerco negli header
                        for (int k =0; k<saved.headers().size(); k++) {
        
                                HttpHeader h = saved.headers().get(k);
        
                                if (h.value().contains("§")) {
                                        long count = h.value().chars().filter(ch -> ch == '§').count();
                                        if (count % 2 == 0){
                                                String[] parts = h.value().split("§");
        
                                                if (parts[1].equals("")) {
                                                        this.logging.logToOutput("There is only one § into the body");
                                                        return null;
                                                } else {
                                                        for(int i =1; i<parts.length; i+=2){
                                                                String value = parts[i];
                                                                if (isJWT(value)){
                                                                        if(value.equals(null)){
                                                                                this.logging.logToOutput("There is no JWT in the current response for the same header");
                                                                                return null;
                                                                        }
                                                                        if(!isJWT(extractJwts(response.headers().get(k).value()).get(0))){
                                                                                this.logging.logToOutput("The header in the current response in the same position of the response saved is not a jwt");
                                                                                return null;
                                                                        } else {
                                                                                headers.add(HttpHeader.httpHeader("Authorization", extractJwts(response.headers().get(k).value()).get(0)));
                                                                        }
                                                                                
                                                                } else if (isBasicAuth(value)){
                                                                        if(value.equals(null)){
                                                                                this.logging.logToOutput("There is no Basic in the current response for the same header");
                                                                                return null;
                                                                        }
                                                                        if(!isBasicAuth(extractBasicAuth(response.headers().get(k).value()).get(0))){
                                                                                this.logging.logToOutput("The header in the current response in the same position of the response saved is not a basic");
                                                                                return null;
                                                                        } else {
                                                                                headers.add(HttpHeader.httpHeader("Authorization", extractBasicAuth(response.headers().get(k).value()).get(0)));
                                                                        } 
                                                                } else if(h.name().equals("Set-Cookie")){

                                                                        String savedCookieName = value.split("=")[0];
                                                                        String newCookieValue = "";
                                                                        String newCookieName = "";

                                                                        for(HttpHeader hr : response.headers()){
                                                                                if (hr.name().equals("Set-Cookie")){
                                                                                        newCookieName = hr.value().trim().split(";")[0].split("=")[0];
                                                                                        if (savedCookieName.equals(newCookieName)){
                                                                                                newCookieValue = hr.value().trim().split(";")[0].split("=")[1];
                                                                                                break;
                                                                                        }
                                                                                }
                                                                        }
                                                                        headers.add(HttpHeader.httpHeader("Cookie", newCookieName + "=" +newCookieValue));
        
                                                                } else {
                                                                        HttpHeader customHeader = response.header(h.name());
                                                                        headers.add(HttpHeader.httpHeader(customHeader.name(), customHeader.value()));
                                                                }
                                                        }
                                                }
        
                                        } else {
                                                this.logging.logToOutput("The number of § is not even");
                                                return null;
                                        }
                                }
                        }
                        //cerco nel body
                        String bearer = "";
                        String basic = "";
                        if (saved.bodyToString().contains("§")){
                                long count = saved.bodyToString().chars().filter(ch -> ch == '§').count();
                                        if (count % 2 == 0){
                                                String[] parts = saved.bodyToString().split("§");
                                                if (parts[1].equals("")) {
                                                        this.logging.logToOutput("There is only one § into the body");
                                                        return null;
                                                } else {
                                                        for(int i =1; i<parts.length; i+=2){
                                                                String value = parts[1];
                                                                if(isJWT(value)){
                                                                        bearer = value;
                                                                } else if (isBasicAuth(value)) {
                                                                        basic = value;
                                                                }
                                                        }
                                                }
                                        }
                                        else{
                                                this.logging.logToOutput("The number of § is not even");
                                                return null;
                                        }

                                        Pattern pattern;
                                        if(basic.isBlank()){
                                                pattern = jwtPattern;
                                        } else {
                                                pattern = basic2Pattern;
                                        }
                                        
                                        List<String> tokens = new ArrayList<>();
                                        Matcher matcher = pattern.matcher(saved.bodyToString());
                                        int position = 0;

                                        while (matcher.find()) {
                                                
                                                tokens.add(matcher.group());
                                                if(matcher.group().equals(bearer)){
                                                        break;
                                                }   
                                                position++;
                                        }
                                        //poi prendo quello della risposta corrente e lo aggiungo alla lista degli header da aggiungere
                                        matcher = pattern.matcher(response.bodyToString());
                                        int cnt =0;
                                        while (matcher.find()){
                                                String currentToken = matcher.group();
                                                if(cnt==position){
                                                        if(isJWT(currentToken)){
                                                                headers.add(HttpHeader.httpHeader("Authorization", currentToken));
                                                        } else if(isBasicAuth(currentToken)){
                                                                headers.add(HttpHeader.httpHeader("Authorization", currentToken));
                                                        }
                                                        
                                                        break;
                                                }
                                                cnt++;
                                        }
                        }
                } 
                // Otherwise, if no headers are present, use the entire configured response.
                else {
                        //headers
                        for (int k =0; k<response.headers().size(); k++) {
                                HttpHeader h = response.headers().get(k);
                                String value = h.value();
                                if (isJWT(value)){
                                        if(value.equals(null)){
                                                this.logging.logToOutput("There is no JWT in the current response for the same header");
                                                return null;
                                        } else {
                                                headers.add(HttpHeader.httpHeader("Authorization", extractJwts(response.headers().get(k).value()).get(0)));
                                        }
                                                
                                } else if (isBasicAuth(value)){
                                        if(value.equals(null)){
                                                this.logging.logToOutput("There is no Basic in the current response for the same header");
                                                return null;
                                        } else {
                                                headers.add(HttpHeader.httpHeader("Authorization", extractBasicAuth(response.headers().get(k).value()).get(0)));
                                        }
                                } else if(h.name().equals("Set-Cookie")){
                                        value = response.headers().get(k).value();
                                        headers.add(HttpHeader.httpHeader("Cookie", value));
                                } 
                        }
                        //body
                        List<String> jwts = extractJwts(response.bodyToString());
                        if (!jwts.isEmpty()) {
                                headers.add(HttpHeader.httpHeader("Authorization", jwts.get(0)));
                        } else {
                                List<String> basicAuths = extractBasicAuth(response.bodyToString());
                                if (!basicAuths.isEmpty()) {
                                        headers.add(HttpHeader.httpHeader("Authorization", basicAuths.get(0)));
                        }
                        }

                        
                }
                return headers;
        }

        /**
         * Executes the configured token acquisition workflow.
         * Performs all requests in the req_res list sequentially, carrying forward
         * session data (cookies, headers, tokens) between requests.
         *
         * The workflow:
         * 1. Iterate through each configured request
         * 2. Extract tokens/headers from the previous response
         * 3. Inject those tokens/headers into the next request
         * 4. Send the request and capture the response
         * 5. Extract final tokens from the last response
         *
         * @return Headers containing the fresh authentication tokens, or null if workflow fails
         */
        private ArrayList<HttpHeader> doRequests() {

                List<HttpRequestResponse> currentReqRes = new ArrayList<>(Arrays.asList(HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(), HttpResponse.httpResponse())));
                ArrayList<HttpHeader> newHeaders = new ArrayList<>();
                this.session = null;

                // Execute the token acquisition workflow
                for(int j=1; j < req_res.size(); j++){

                        currentReqRes.add(HttpRequestResponse.httpRequestResponse(req_res.get(j).request(), HttpResponse.httpResponse()));
                        HttpResponse prevResponse = req_res.get(j-1).response();

                        // This logic only applies to subsequent requests after the first. 
                        if(!prevResponse.toString().equals("")){
                                ArrayList<HttpHeader> headers = takeSession(currentReqRes.get(j-1).response(), prevResponse);
                                currentReqRes.set(j, HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(editRequest(currentReqRes.get(j).request(), headers).toByteArray()), HttpResponse.httpResponse()));
                        }
                        HttpService service;

                        String host = req_res.get(j).request().header("Host").value().split(":")[0];
                        if(req_res.get(j).request().header("Host").value().split(":").length > 1 ){

                                int port;
                                try {
                                        port = Integer.parseInt(req_res.get(j).request().header("Host").value().split(":")[1]);
                                } catch (Exception e) {
                                        JOptionPane.showMessageDialog(null, e, "The provided port number is invalid", JOptionPane.ERROR_MESSAGE);
                                        logging.logToOutput("e.: " + e.getStackTrace().toString());
                                        return null;
                                }
                                service = HttpService.httpService(host, port, !http_check.get(j));
                        } else {
                                service = HttpService.httpService(host, !http_check.get(j));
                        }

                        //HttpService.httpService(host, ((http_check.get(j)) ? false : true));

                        HttpRequest request = HttpRequest.httpRequest(service, currentReqRes.get(j).request().toByteArray());

                        try {
                                currentReqRes.set( j, montoyaApi.http().sendRequest(request, HttpMode.AUTO));

                        } catch (Exception e) {

                                // Handle the exception here
                                this.logging.logToOutput("Error during the request " + e.getStackTrace().toString());
                                return null;
                        }

                        if (currentReqRes.get(j).response().toByteArray().length() == 0){
                                this.logging.logToOutput("Empty response received");
                                return null;
                        } else {

                                if(j==req_res.size()-1){
                                        newHeaders = takeSession(currentReqRes.get(j).response(), req_res.get(j).response());
                                }
                        }
                }

                return newHeaders;
        }

        /**
         * Handles outgoing HTTP requests from Burp Suite tools.
         * Automatically injects fresh authentication tokens into requests if:
         * - The extension is active
         * - The request comes from a monitored tool
         * - Fresh tokens are available in the session
         *
         * @param requestToBeSent The HTTP request about to be sent
         * @return Action to take (continue with modified or original request)
         */
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

                // Pass through requests unchanged if extension is inactive
                if (!active_state.get(0)) {
                        this.session = null;
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                }
                // Check if the request comes from a monitored Burp tool
                ToolType[] burpTools = ToolType.values();
                Boolean foundTool = false;

                if(tools_check.get(0)){
                        // "All tools" is selected
                        foundTool = true;
                } else {
                        // Check if specific tool is selected
                        for(int k=1; k<tools_check.size(); k++){
                                if(tools_check.get(k)){
                                        if (burpTools[k].name().equals(requestToBeSent.toolSource().toolType().name())){
                                                foundTool = true;
                                        }
                                }
                        }
                }

                // Inject tokens if tool is monitored and we have fresh tokens
                if (foundTool && this.session!=null) {
                        if (!requestToBeSent.isInScope()) {
                                this.logging.logToOutput("Error: URL not in scope: " + requestToBeSent.url());
                                return RequestToBeSentAction.continueWith(requestToBeSent);
                        } else {
                        return RequestToBeSentAction.continueWith(editRequest(requestToBeSent, this.session));
                }
                } else {
                        this.session = null;
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                }


        }

        /**
         * Handles incoming HTTP responses from Burp Suite tools.
         * Monitors responses for expired token conditions and automatically:
         * 1. Detects when a token has expired based on configured patterns
         * 2. Executes the token refresh workflow
         * 3. Retries the original request with the fresh token
         * 4. Returns the new response to the user
         *
         * This creates a seamless experience where expired tokens are automatically
         * refreshed without user intervention.
         *
         * @param responseReceived The HTTP response that was received
         * @return Action to take (continue with original or replacement response)
         */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {

        // Pass through responses unchanged if extension is inactive
        if (!active_state.get(0)) {
                this.session = null;
                isTokenNew = false;
                return ResponseReceivedAction.continueWith(responseReceived);
        }
        // Check if the response comes from a monitored Burp tool
        ToolType[] burpTools = ToolType.values();
        Boolean foundTool = false;

        if(tools_check.get(0)){
                // "All tools" is selected
                foundTool = true;
        } else {
                // Check if specific tool is selected
                for(int k=1; k<tools_check.size(); k++){
                        if(tools_check.get(k)){
                                if (burpTools[k].name().equals(responseReceived.toolSource().toolType().name())){
                                        foundTool = true;
                                }
                        }
                }
        }

                if (!foundTool) {
                this.session = null;
                isTokenNew = false;
                return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Check if the response matches any expired token condition
        Short responseCode = responseReceived.statusCode();
        String responseBody = responseReceived.bodyToString();
        Boolean found = false;

        // Iterate through configured expired conditions
        for(HttpResponse e : expired_conditions){
            Short eCode = e.statusCode();
            String eBody = e.bodyToString();

            if(e.contains("§", false)){
                // Expired condition has § markers - check if marked text is in response
                ByteArray eByteArray = e.toByteArray();
                int occur = eByteArray.countMatches("§");
                if(occur % 2 ==0){
                        String[] eSplitted = e.toString().split("§");
                        for(int i=1; i<eSplitted.length; i+=2){
                                if(responseReceived.toString().contains(eSplitted[i])){
                                        found = true;
                                        break;
                                }
                        }
                }
            } else {
                // No markers - check exact match of status code and body
                if (responseCode.equals(eCode) && responseBody.equals(eBody)){
                        found = true;
                        break;
                    }
            }
        }

        // Handle expired token condition
        if (found){

                if(isTokenNew){
                        // We just refreshed the token, but still got expired condition
                        // Avoid infinite loop - don't refresh again
                        isTokenNew=false;
                        return ResponseReceivedAction.continueWith(responseReceived);

                } else{
                        // Token has expired - refresh it
                        this.session = doRequests();

                        isTokenNew=true;

                        // Retry the original request with fresh token
                        if(session.size() > 0) {

                                HttpRequest oldRequest = responseReceived.initiatingRequest();
                                HttpRequest editedRequest = editRequest(oldRequest, this.session);
                                HttpRequestResponse newRequestResponse = montoyaApi.http().sendRequest(editedRequest);

                                // Check if the retry succeeded (different response than expired condition)
                                if((newRequestResponse.response().statusCode() !=  responseCode) || !newRequestResponse.response().bodyToString().equals(responseBody)){
                                        // Success - return the new response
                                        return ResponseReceivedAction.continueWith(newRequestResponse.response());
                                } else {
                                        // Still getting expired response - return original
                                        return ResponseReceivedAction.continueWith(responseReceived);
                                }
                        } else {
                                // Token refresh failed - return original response
                                return ResponseReceivedAction.continueWith(responseReceived);
                        }
                }


        } else {
            // No expired condition found - pass through the response
            isTokenNew=false;
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        }

}