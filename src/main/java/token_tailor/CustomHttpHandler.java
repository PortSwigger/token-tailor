package token_tailor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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

public class CustomHttpHandler implements HttpHandler {
        Logging logging;
        MontoyaApi montoyaApi;
        PersistedList<HttpRequestResponse> req_res;
        PersistedList<HttpResponse> expired_conditions;
        PersistedList<Boolean> active_state;
        PersistedList<Boolean> tools_check;
        PersistedList<Boolean> http_check;

        ArrayList<HttpHeader> session;
        Map<Instant, HttpResponse> tokenHistory = new HashMap<>();
        Boolean isTokenNew = false;

        public CustomHttpHandler(MontoyaApi montoyaApi, Logging logging, PersistedList<HttpRequestResponse> req_res, PersistedList<HttpResponse> expired_conditions, PersistedList<Boolean> active_state , PersistedList<Boolean> tools_check, PersistedList<Boolean> http_check ) {
                
                this.logging = logging;
                this.montoyaApi = montoyaApi;

                this.req_res = req_res;
                this.expired_conditions = expired_conditions;
                this.active_state = active_state;
                this.tools_check = tools_check;
                this.http_check = http_check;
        }

        private List<String> extractJwts(String text) {
                List<String> jwts = new ArrayList<>();
                String pattern = "\\b(eyJ[A-Za-z0-9-_]+)\\.(eyJ[A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\b";
                Matcher matcher = Pattern.compile(pattern , Pattern.CASE_INSENSITIVE).matcher(text);
        
                while (matcher.find()) {
                        jwts.add(matcher.group());
                }

                return jwts;
        }

        private boolean isJWT(String value) {
                String jwtRegex = "\\b(eyJ[A-Za-z0-9-_]+)\\.(eyJ[A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\b";
                Pattern pattern = Pattern.compile(jwtRegex);
                Matcher matcher = pattern.matcher(value);

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
        
        private static boolean isBasicAuth(String input) {
            try {
                // Check if the input is a valid Base64 string
                byte[] decodedBytes = Base64.getDecoder().decode(input);
                String decodedString = new String(decodedBytes);
    
                // Check if the decoded string matches the "string:string" format
                String stringStringRegex = "^[^:]+:[^:]+$";
                Pattern pattern = Pattern.compile(stringStringRegex);
                Matcher matcher = pattern.matcher(decodedString);
    
                return matcher.matches();
            } catch (IllegalArgumentException e) {
                // Catch the exception if the input is not a valid Base64 string
                return false;
            }
        }

        private List<String> extractBasicAuth(String text) {
                List<String> basics = new ArrayList<>();
                String pattern = "[A-Za-z0-9+]{6,}={0,}";
                Matcher matcher = Pattern.compile(pattern , Pattern.CASE_INSENSITIVE).matcher(text);
        
                while (matcher.find()) {
                        basics.add(matcher.group());
                }
                
                return basics;
        }
        
        // Given a request, adds or modifies the headers present in the array.
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

        // Extracts the necessary headers from the given response object. 
        // These headers will be used to add new or update existing header values.
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
                                                pattern = Pattern.compile("\\b(eyJ[A-Za-z0-9-_]+)\\.(eyJ[A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\b", Pattern.CASE_INSENSITIVE);
                                        } else {
                                                pattern = Pattern.compile("^[^:]+:[^:]+$", Pattern.CASE_INSENSITIVE);
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

        private ArrayList<HttpHeader> doRequests() {

                List<HttpRequestResponse> currentReqRes = new ArrayList<>(Arrays.asList(HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(), HttpResponse.httpResponse())));
                ArrayList<HttpHeader> newHeaders = new ArrayList<>();
                this.session = null;
                
                // Start the main execution flow.
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

                        if (!request.isInScope()) {
                                this.logging.logToOutput("Error: URL not in scope: " + currentReqRes.get(j).request().url());
                                return null;
                        } else {

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
                }

                return newHeaders;
        }

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                
                // Do normal request if the active condition is false
                if (!active_state.get(0)) {
                        this.session = null;
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                }
                ToolType[] burpTools = ToolType.values();
                Boolean foundTool = false;

                if(tools_check.get(0)){
                        foundTool = true;
                } else {
                        for(int k=1; k<tools_check.size(); k++){
                                if(tools_check.get(k)){
                                        if (burpTools[k].name().equals(requestToBeSent.toolSource().toolType().name())){
                                                foundTool = true;
                                        }
                                }
                        }
                }

                if (foundTool && this.session!=null) {
                        return RequestToBeSentAction.continueWith(editRequest(requestToBeSent, this.session));
                } else {
                        this.session = null;
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                }
                
                
        }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        
        // Do normal request if the active condition is false
        if (!active_state.get(0)) {
                this.session = null;
                isTokenNew = false;
                return ResponseReceivedAction.continueWith(responseReceived);
        }
        ToolType[] burpTools = ToolType.values();
        Boolean foundTool = false;

        if(tools_check.get(0)){
                foundTool = true;
        } else {
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

        // check in each payload request if there is the error condition
        Short responseCode = responseReceived.statusCode();
        String responseBody = responseReceived.bodyToString();
        Boolean found = false;

        // Start iterating through the expired conditions
        for(HttpResponse e : expired_conditions){
            Short eCode = e.statusCode();
            String eBody = e.bodyToString();

            if(e.contains("§", false)){
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
                if (responseCode.equals(eCode) && responseBody.equals(eBody)){
                        found = true;
                        break;
                    }
            }
        }

        if (found){
                //Boolean same_responses = false;
                //Instant currentTime = Instant.now();

                if(isTokenNew){
                        isTokenNew=false;
                        return ResponseReceivedAction.continueWith(responseReceived);

                } else{
                        // take the new headers
                        this.session = doRequests();

                        isTokenNew=true;
                        
                        // do again the failed http request with the new bearer
                        if(session.size() > 0) {
                                                
                                HttpRequest oldRequest = responseReceived.initiatingRequest();
                                HttpRequest editedRequest = editRequest(oldRequest, this.session);
                                HttpRequestResponse newRequestResponse = montoyaApi.http().sendRequest(editedRequest);

                                if((newRequestResponse.response().statusCode() !=  responseCode) || !newRequestResponse.response().bodyToString().equals(responseBody)){
                                        return ResponseReceivedAction.continueWith(newRequestResponse.response());
                                } else {
                                        //do nothing
                                        return ResponseReceivedAction.continueWith(responseReceived); 
                                }
                        } else {
                                //do nothing - no headers to be added were found
                                return ResponseReceivedAction.continueWith(responseReceived);  
                        }
                }
                
                
        } else {
            //do nothing - no expired condition found
            isTokenNew=false;
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        }

}