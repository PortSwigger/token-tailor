package token_tailor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.ui.UserInterface;

public class App implements BurpExtension {

        MontoyaApi api;
        Logging logging;
        UserInterface userGUI;

        PersistedList<Boolean> active_state = PersistedList.persistedBooleanList();
        PersistedList<Boolean> http_check = PersistedList.persistedBooleanList();
        PersistedList<HttpRequestResponse> req_res = PersistedList.persistedHttpRequestResponseList();
        PersistedList<HttpResponse> expired_conditions = PersistedList.persistedHttpResponseList();
        PersistedList<Boolean> tools_check = PersistedList.persistedBooleanList();

         @Override
        public void initialize(MontoyaApi api) {
                this.api = api;
                this.logging = api.logging();
                api.extension().setName("Token Tailor");
                this.logging.logToOutput("Token Tailor Loaded");

                api.userInterface().registerSuiteTab("Token Tailor", new TokenTailorGUI(api, logging,  req_res, expired_conditions, active_state, tools_check, http_check) );

                api.http().registerHttpHandler(new CustomHttpHandler(api, logging,  req_res, expired_conditions, active_state, tools_check, http_check));
        }

}