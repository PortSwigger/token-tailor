package token_tailor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.ui.UserInterface;

/**
 * Token Tailor - Main entry point for the Burp Suite extension.
 *
 * This extension automates the process of obtaining and refreshing authentication tokens
 * (JWT and Basic Auth) during security testing. It intercepts HTTP traffic, detects
 * expired tokens, and automatically refreshes them using a configured token acquisition workflow.
 *
 * Key Features:
 * - Automatic token detection (JWT and Basic Authentication)
 * - Token expiration detection based on response patterns
 * - Automatic token refresh workflow
 * - Support for multi-step authentication flows
 * - Configurable tool scope (which Burp tools to monitor)
 * - Import/Export configuration support
 *
 * @author br1
 */
public class App implements BurpExtension {

        // Core Burp Suite API references
        MontoyaApi api;
        Logging logging;
        UserInterface userGUI;

        // Persistent storage for extension configuration
        // These lists survive between Burp Suite sessions
        PersistedList<Boolean> active_state = PersistedList.persistedBooleanList();           // Extension on/off state
        PersistedList<Boolean> http_check = PersistedList.persistedBooleanList();             // HTTP/HTTPS settings per request
        PersistedList<HttpRequestResponse> req_res = PersistedList.persistedHttpRequestResponseList();  // Token acquisition workflow
        PersistedList<HttpResponse> expired_conditions = PersistedList.persistedHttpResponseList();     // Expired token patterns
        PersistedList<Boolean> tools_check = PersistedList.persistedBooleanList();            // Which Burp tools to monitor

        /**
         * Initializes the Token Tailor extension.
         * Called by Burp Suite when the extension is loaded.
         *
         * This method:
         * 1. Sets up the extension name
         * 2. Registers the GUI tab for user configuration
         * 3. Registers the HTTP handler for automatic token management
         *
         * @param api The Montoya API provided by Burp Suite for extension integration
         */
         @Override
        public void initialize(MontoyaApi api) {
                this.api = api;
                this.logging = api.logging();

                // Set the extension name as it appears in Burp Suite
                api.extension().setName("Token Tailor");
                this.logging.logToOutput("Token Tailor Loaded");

                // Register the GUI tab where users configure token acquisition workflows
                api.userInterface().registerSuiteTab("Token Tailor", new TokenTailorGUI(api, logging,  req_res, expired_conditions, active_state, tools_check, http_check) );

                // Register the HTTP handler that intercepts traffic and manages tokens
                api.http().registerHttpHandler(new CustomHttpHandler(api, logging,  req_res, expired_conditions, active_state, tools_check, http_check));
        }

}