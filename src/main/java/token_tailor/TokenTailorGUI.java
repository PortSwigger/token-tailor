package token_tailor;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.text.Style;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 *
 * @author br1
 */

public class TokenTailorGUI extends JPanel {

    Logging logging;
    MontoyaApi montoyaApi;

    PersistedList<HttpRequestResponse> req_res;
    PersistedList<HttpResponse> expired_conditions;
    PersistedList<Boolean> active_state;
    PersistedList<Boolean> tools_check;
    PersistedList<Boolean> http_check;

    private ArrayList<HttpRequestEditor> editor_requests;
    private ArrayList<HttpResponseEditor> editor_responses;
    private ArrayList<HttpResponseEditor> editor_expired_conditions;
    private ArrayList<JCheckBox> checkboxes_tools_check;
    private ArrayList<JToggleButton> checkboxes_http_check;

    boolean importFlow;

    private final Frame burpFrame;


    public TokenTailorGUI(MontoyaApi montoyaApi, Logging logging, PersistedList<HttpRequestResponse> req_res, PersistedList<HttpResponse> expired_conditions, PersistedList<Boolean> active_state, PersistedList<Boolean> tools_check, PersistedList<Boolean> http_check) {
        this.logging = logging;
        this.montoyaApi = montoyaApi;

        this.req_res = req_res;
        this.expired_conditions = expired_conditions;
        this.active_state = active_state;
        this.tools_check = tools_check;
        this.http_check = http_check;

        this.burpFrame = montoyaApi.userInterface().swingUtils().suiteFrame();

        initComponents();
    }

    private void initComponents() {

        jScrollPane9 = new JScrollPane();
        jPanel3 = new JPanel();
        impExp = new JButton("IMPORT");
        activeState = new JToggleButton("OFF", false);
        title = new JLabel("Token Tailor");
        jTabbedPane2 = new JTabbedPane();
        jPanel1 = new JPanel();
        jPanel8 = new JPanel();
        jTabbedPane3 = new JTabbedPane();
        jPanel9 = new JPanel();
        jTabbedPane4 = new JTabbedPane();
        jButton4 = new JButton();
        jPanel4 = new JPanel();
        allTools = new JCheckBox();
        checkboxList = new ArrayList<>();
        jPanel6 = new JPanel();
        jScrollPane7 = new JScrollPane();
        logTextArea = new JTextArea(10, 30);
        jLabel7 = new JLabel();

        importFlow = false;
    
        editor_requests = new ArrayList<>();
        editor_responses = new ArrayList<>();
        editor_expired_conditions = new ArrayList<>();
        checkboxes_tools_check = new ArrayList<>();
        checkboxes_http_check = new ArrayList<>();
    
        active_state.add(activeState.isSelected());
    
        jScrollPane9.getVerticalScrollBar().setUnitIncrement(16);
        jScrollPane9.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
    
        jPanel3.setBorder(BorderFactory.createEmptyBorder());
    
        impExp.addActionListener(e -> {
            boolean status = active_state.get(0);
            String configuration = "";
            if (status) {
                configuration = currentConfiguration();
                exportJsonFile(configuration);
            } else {
                configuration = uploadJsonFile();
                setNewConfiguration(configuration);
            }
        });
        
        // start header panel
        activeState.addActionListener(e -> {

                activeState.setText("Processing...");
                logTextArea.insert(getFormattedTime() + " - Updating extension status...\n",0);
                // ----------------------
                //Trying to start the extension
                if (activeState.isSelected()) {
                        // req_res checks
                        for (int i = 1; i < req_res.size(); i++) {
                                if (i == 0 && req_res.get(i).request().contains("§", false)) {
                                        activeError("Request 1 contains §");
                                        return;
                                } else if (req_res.get(i).request().toString().equals("")) {
                                        activeError("Request " + i + ": has the request empty");
                                        return;
                                } else if (req_res.get(i).response().toString().equals("")) {
                                        activeError("Request " + i + ": has the response empty");
                                        return;
                                } else if (req_res.get(i).response().toByteArray().countMatches("§") % 2 != 0) {
                                        activeError("Request " + i + ": the response has to have a even number of §");
                                        return;                           
                                    } else if (i == (req_res.size() - 1)) {
                                        HttpResponse res = req_res.get(i).response();

                                        // work on the response to find the bearer
                                        String jwtRegex = "\\b(eyJ[A-Za-z0-9-_]+)\\.(eyJ[A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\b";
                                        String basicAuthRegex = "[A-Za-z0-9+]{6,}={0,}";
                                        Pattern jwtPattern = Pattern.compile(jwtRegex);
                                        Pattern basicAuthPattern = Pattern.compile(basicAuthRegex);

                                        // check in all the response
                                        Matcher jwtMatcher = jwtPattern.matcher(res.toString());
                                        Matcher basicAuthMatcher = basicAuthPattern.matcher(res.toString());
                                        Boolean found = false;
                                    
                                        if (jwtMatcher.find()) {

                                            // Split the matched token into parts
                                            String[] parts = jwtMatcher.group(0).split("\\.");
                                            if (parts.length == 3) {
                                    
                                                String headerEncoded = parts[0].replace('-', '+')
                                                        .replace('_', '/');
                                                while (headerEncoded.length() % 4 != 0) {
                                                    headerEncoded += "=";
                                                }
                                                byte[] decodedBytes = Base64.getDecoder()
                                                        .decode(headerEncoded);
                                                String decodedHeader = new String(decodedBytes);
                                                if (decodedHeader.startsWith("{\"alg\":")) {
                                                    found = true;
                                                }
                                            }
                                        } else if (basicAuthMatcher.find()) {
                                            while(basicAuthMatcher.find()){                                                
                                        
                                                try {
                                                    int start = basicAuthMatcher.start();
                                                    int end = basicAuthMatcher.end();

                                                    String encodedCredentials = res.toString().substring(start, end);
                                                    
                                                    // Decode the Base64 string
                                                    byte[] decodedBytes = Base64.getDecoder().decode(encodedCredentials);
                                                    String decodedCredentials = new String(decodedBytes);
                                        
                                                    // Check if the decoded string matches the "string:string" format
                                                    String[] parts = decodedCredentials.split(":");
                                                    if (parts.length == 2) {
                                                        found = true;
                                                        break; // Exit the loop if a valid token is found
                                                    }
                                                } catch (IllegalArgumentException ex) {
                                                    found =false;
                                                }
                                            }
                                        
                                            if (!found) {
                                                activeError("Request " + i + ": there is no valid Basic Authentication token in the last response");
                                                return;
                                            }
                                        }
                                    
                                        if (!found) {
                                            activeError("Request " + i + ": there is no JWT or Basic Authentication token in the last response");
                                            return;
                                        }
                                    }
                        }

                        // ------------------------------
                        // expired_conditions checks                             
                        for (int i = 1; i < expired_conditions.size(); i++) {
                                if (expired_conditions.get(i).toString().equals("")) {
                                        activeError("Expired Condition" + i + " has the response empty");
                                        return;
                                } else if (expired_conditions.get(i).toByteArray().countMatches("§")
                                                % 2 != 0) {
                                        activeError("Expired Condition " + i + ": the number of § has to be even");
                                        return;
                                }
                        }

                        // ------------------------------
                        // tools_checks checks
                        if(tools_check.get(0)){
                                for (int i = 1; i < tools_check.size(); i++) {
                                        if(tools_check.get(i)){
                                                activeError("If 'Everywhere' is selected, no other checkbox should be selected");
                                                return;
                                        }
                                }
                        } else {
                                Boolean check = false;
                                for (int i = 1; i < tools_check.size(); i++) {
                                        if(tools_check.get(i)){
                                                check = true;
                                        }
                                }
                                if (!check){
                                        activeError("At least one checkbox should be true");
                                        return;
                                } ;

                        }

                        // ------------------------------
                        // http_check checks
                        for(int i=1; i<http_check.size(); i++){
                                if(!(http_check.get(i) instanceof Boolean)){
                                        activeError("HTTP checkbox of Req "+i+"is misconfigured"); 
                                        return;
                                }
                        }
                        // ------------------------------
                        // finally turn on
                        active_state.set(0,true);
                        activeState.setText("ON");
                        impExp.setText("EXPORT");
                        //startMonitoring();
                        logTextArea.insert(getFormattedTime() + " - Token Tailor is Active\n",0); 
                }else {
                        active_state.set(0,false);
                        activeState.setText("OFF");
                        impExp.setText("IMPORT");
                        logTextArea.insert(getFormattedTime() +" - Token Tailor was turned off\n", 0);                }
        
        });
    
        title.setFont(new java.awt.Font("Liberation Sans", 1, 24));
        title.setForeground(new java.awt.Color(255, 255, 255));
        title.setForeground(new java.awt.Color(255, 255, 255));
        title.setHorizontalAlignment(SwingConstants.CENTER);
    
        jTabbedPane2.setBorder(BorderFactory.createEmptyBorder());
        jTabbedPane2.setForeground(new java.awt.Color(255, 102, 0));
        jTabbedPane2.addTab("Domain (define the scope!)", jPanel1);
        jTabbedPane2.addTab("... more Domains with v2.0.0!", jButton4);
        jTabbedPane2.setEnabledAt(1, false);
    
        jPanel8.setBorder(BorderFactory.createEtchedBorder(null, null));
    
        jTabbedPane3.addTab("+", new JPanel());
    
        req_res.add(HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(""), HttpResponse.httpResponse("")));
        http_check.add(false);
        checkboxes_http_check.add(new JToggleButton());
        editor_requests.add(montoyaApi.userInterface().createHttpRequestEditor());
        editor_responses.add(montoyaApi.userInterface().createHttpResponseEditor());
    
        addReq("Request " + jTabbedPane3.getTabCount(), new JPanel(), jTabbedPane3);
        jTabbedPane3.setSelectedIndex(jTabbedPane3.getTabCount() - 1);
    
        jTabbedPane3.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent evt) {
                if (jTabbedPane3.getSelectedIndex() == 0 && importFlow == false) {
                    //if (active_state.get(0)) { active_state.set(0, false);};
                    turnoffTokenTailor();
                    jTabbedPane3.removeChangeListener(this);
                    addReq("Request " + (jTabbedPane3.getTabCount()), new JPanel(), jTabbedPane3);
                    jTabbedPane3.setSelectedIndex(jTabbedPane3.getTabCount() - 1);
                    jTabbedPane3.addChangeListener(this);
                }
            }
        });
    
        jPanel9.setBorder(BorderFactory.createEtchedBorder(null, null));
        jTabbedPane4.addTab("+", new JPanel());
    
        expired_conditions.add(HttpResponse.httpResponse());
        editor_expired_conditions.add(montoyaApi.userInterface().createHttpResponseEditor());
    
        addExp("Expired Condition " + jTabbedPane4.getTabCount(), new JPanel(), jTabbedPane4);
        jTabbedPane4.setSelectedIndex(jTabbedPane4.getTabCount() - 1);
    
        jTabbedPane4.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent evt) {
                turnoffTokenTailor();
                if (jTabbedPane4.getSelectedIndex() == 0 && importFlow == false) {
                    jTabbedPane4.removeChangeListener(this);
                    addExp("Expired Condition " + (jTabbedPane4.getTabCount()), new JPanel(), jTabbedPane4);
                    jTabbedPane4.setSelectedIndex(jTabbedPane4.getTabCount() - 1);
                    jTabbedPane4.addChangeListener(this);
                }
            }
        });
    
        jPanel4.setBorder(BorderFactory.createTitledBorder(null, "Check Traffic From: ", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Liberation Sans", 0, 15), new java.awt.Color(255, 102, 0)));
        allTools.setText("All");
        allTools.setSelected(true);
        tools_check.add(allTools.isSelected());
        checkboxes_tools_check.add(allTools);
    
        ToolType[] burpTools = ToolType.values();
        for (int k = 1; k < burpTools.length; k++) {
            JCheckBox checkTool = new JCheckBox(toUpperCamelCase(burpTools[k].name()));
            tools_check.add(checkTool.isSelected());
            final int position = k;
            checkTool.addActionListener(e -> {
                turnoffTokenTailor();
                tools_check.set(position, checkTool.isSelected());
                unselectAllTools(position);
            });
            checkboxList.add(checkTool);
            checkboxes_tools_check.add(checkTool);
        }
    
        allTools.addActionListener(e -> {
            turnoffTokenTailor();
            tools_check.set(0, allTools.isSelected());
            selectAllTools();
        });
    
        jPanel6.setBorder(BorderFactory.createEtchedBorder(null, null));
        logTextArea.setColumns(20);
        logTextArea.setFocusable(false);
        logTextArea.setLineWrap(true);
        logTextArea.setRows(5);
        logTextArea.setBackground(new Color(0, 0, 0, 0));
        logTextArea.setBackground(new Color(255, 255, 255, 128));
        logTextArea.setOpaque(false);
        jScrollPane7.setViewportView(logTextArea);
        jScrollPane7.getVerticalScrollBar().setUnitIncrement(16);
    
        jLabel7.setForeground(new java.awt.Color(255, 102, 0));
        jLabel7.setHorizontalAlignment(SwingConstants.CENTER);
        jLabel7.setText("GUI Log");
    
        jScrollPane9.setViewportView(jPanel3);
    
        this.setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
    
        constraints.fill = GridBagConstraints.BOTH;
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = 1.0;
        constraints.weighty = 1.0;
    
        JPanel root = new JPanel(new GridBagLayout());
        GridBagConstraints gbc_root = new GridBagConstraints();
    
        // Set the layout and constraints for jPanel4
        jPanel4.setLayout(new GridBagLayout());
        GridBagConstraints gbc_tools = new GridBagConstraints();
        gbc_tools.gridx = 0;
        gbc_tools.gridy = 0;
        gbc_tools.weightx = 0.1;
        gbc_tools.anchor = GridBagConstraints.WEST;
        jPanel4.add(allTools, gbc_tools);

        for (int i = 0; i < checkboxList.size(); i++) {
        gbc_tools.gridx = i + 1;
        gbc_tools.gridy = 0;
        gbc_tools.weightx = 0.1;
        gbc_tools.anchor = GridBagConstraints.WEST;
        jPanel4.add(checkboxList.get(i), gbc_tools);
        }

        JScrollPane scroll_tools = new JScrollPane(jPanel4);
        scroll_tools.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scroll_tools.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll_tools.setBorder(BorderFactory.createEmptyBorder());

        gbc_root.gridx = 0;
        gbc_root.gridy = 0;
        gbc_root.gridwidth = GridBagConstraints.REMAINDER;
        gbc_root.gridheight = 1;
        gbc_root.weightx = 1.0;
        gbc_root.weighty = 0.08;
        gbc_root.insets = new Insets(5, 5, 0, 5);

        gbc_root.fill = GridBagConstraints.BOTH;
        root.setPreferredSize(new Dimension(1280, 1080));
        root.add(scroll_tools, gbc_root);

    
        jPanel1.setLayout(new GridBagLayout());
        gbc_root.gridx = 0;
        gbc_root.gridy = 1;
        gbc_root.gridwidth = GridBagConstraints.REMAINDER;
        gbc_root.gridheight = 1;
        gbc_root.weightx = 1.0;
        gbc_root.weighty = 0.92;
        gbc_root.fill = GridBagConstraints.BOTH;
        root.add(jTabbedPane2, gbc_root);
    
        GridBagConstraints gbc_domains = new GridBagConstraints();
        jPanel8.setLayout(new GridBagLayout());
        gbc_domains.gridx = 0;
        gbc_domains.gridy = 0;
        gbc_domains.gridwidth = GridBagConstraints.REMAINDER;
        gbc_domains.gridheight = 1;
        gbc_domains.weightx = 1.0;
        gbc_domains.weighty = 0.5;
        gbc_domains.fill = GridBagConstraints.BOTH;
        jPanel1.add(jPanel8, gbc_domains);
    
        gbc_domains.gridx = 0;
        gbc_domains.gridy = 0;
        gbc_domains.gridwidth = GridBagConstraints.REMAINDER;
        gbc_domains.gridheight = GridBagConstraints.REMAINDER;
        gbc_domains.weightx = 1.0;
        gbc_domains.weighty = 1.0;
        gbc_domains.fill = GridBagConstraints.BOTH;
        jPanel8.add(jTabbedPane3, gbc_domains);
    
        jPanel9.setLayout(new GridBagLayout());
        gbc_domains.gridx = 0;
        gbc_domains.gridy = 1;
        gbc_domains.gridwidth = 1;
        gbc_domains.gridheight = 1;
        gbc_domains.weightx = 0.5;
        gbc_domains.weighty = 0.5;
        gbc_domains.fill = GridBagConstraints.BOTH;
        jPanel1.add(jPanel9, gbc_domains);
    
        gbc_domains.gridx = 0;
        gbc_domains.gridy = 0;
        gbc_domains.gridwidth = GridBagConstraints.REMAINDER;
        gbc_domains.gridheight = GridBagConstraints.REMAINDER;
        gbc_domains.weightx = 1.0;
        gbc_domains.weighty = 1.0;
        gbc_domains.fill = GridBagConstraints.BOTH;
        jPanel9.add(jTabbedPane4, gbc_domains);
    
        jPanel6.setLayout(new GridBagLayout());
        gbc_domains.gridx = 1;
        gbc_domains.gridy = 1;
        gbc_domains.gridwidth = 1;
        gbc_domains.gridheight = 1;
        gbc_domains.weightx = 0.5;
        gbc_domains.weighty = 0.5;
        gbc_domains.fill = GridBagConstraints.BOTH;
        jPanel1.add(jPanel6, gbc_domains);
    
        GridBagConstraints gbc_logs = new GridBagConstraints();
        jLabel7.setHorizontalAlignment(SwingConstants.CENTER);
        gbc_logs.gridx = 0;
        gbc_logs.gridy = 0;
        gbc_logs.gridwidth = GridBagConstraints.REMAINDER;
        gbc_logs.gridheight = 1;
        gbc_logs.weightx = 1.0;
        gbc_logs.weighty = 0.2;
        gbc_logs.fill = GridBagConstraints.BOTH;
        jPanel6.add(jLabel7, gbc_logs);
    
        gbc_logs.gridx = 0;
        gbc_logs.gridy = 1;
        gbc_logs.gridwidth = GridBagConstraints.REMAINDER;
        gbc_logs.gridheight = 1;
        gbc_logs.weightx = 1.0;
        gbc_logs.weighty = 0.8;
        gbc_logs.fill = GridBagConstraints.BOTH;
        jPanel6.add(jScrollPane7, gbc_logs);
    
        JScrollPane scrollPane = new JScrollPane(root);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
    
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = GridBagConstraints.REMAINDER;
        constraints.gridheight = 1;
        constraints.weightx = 1.0;
        constraints.weighty = 1.0;
        constraints.fill = GridBagConstraints.BOTH;
        this.add(scrollPane, constraints);
    
        JPanel footerPanel = new JPanel();
        footerPanel.setBackground(new java.awt.Color(255, 102, 0));
        footerPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbcFooter = new GridBagConstraints();
    
        gbcFooter.gridx = 0;
        gbcFooter.gridy = 0;
        gbcFooter.weightx = 0.05;
        gbcFooter.fill = GridBagConstraints.HORIZONTAL;
        footerPanel.add(activeState, gbcFooter);
    
        gbcFooter.gridx = 1;
        gbcFooter.gridy = 0;
        gbcFooter.weightx = 0.85;
        gbcFooter.fill = GridBagConstraints.HORIZONTAL;
        footerPanel.add(title, gbcFooter);
    
        gbcFooter.gridx = 2;
        gbcFooter.gridy = 0;
        gbcFooter.weightx = 0.03;
        gbcFooter.fill = GridBagConstraints.HORIZONTAL;
        footerPanel.add(impExp, gbcFooter);

        JButton help = new JButton("?");

        help.setFont(new Font("Liberation Sans", Font.BOLD, 20));
        help.setContentAreaFilled(false);
        help.setFocusPainted(false);
        help.setBorderPainted(false);
        help.setForeground(Color.WHITE);

        gbcFooter.gridx = 3;
        gbcFooter.gridy = 0;
        gbcFooter.weightx = 0.02;
        gbcFooter.fill = GridBagConstraints.HORIZONTAL;
        footerPanel.add(help, gbcFooter);

        help.addActionListener(e -> {
            String htmlContent = "<html><body>"
            + "<h3 style='text-align:center;'>Help Resources</h3>"
            + "<p>For more detailed information and guidance, please refer to the following resources:</p>"
            + "<ul>"
            + "<li style='margin-bottom:15px'>ReadMe Documentation: <a href='https://github.com/forteBruno/Token-Tailor'>Token Tailor GitHub Repository</a></li>"
            + "<li>Video Tutorial: <a href='https://www.youtube.com/channel/UCM4rxcHMfGv73GppNEzjQ3g'>Watch the Tutorial on YouTube</a></li>"
            + "</ul>"
            + "<hr>"  
            + "<p>Special thanks to <a href='https://github.com/gand3lf'>Gand3lf</a> for his contributions.</p>"
            + "</body></html>";

        // HTML content
        JEditorPane editorPane = new JEditorPane("text/html", htmlContent);
        editorPane.setEditable(false);
        editorPane.setOpaque(false);
        editorPane.setBorder(BorderFactory.createEmptyBorder());

        // HyperlinkListener to handle link clicks
        editorPane.addHyperlinkListener(new HyperlinkListener() {
            @Override
            public void hyperlinkUpdate(HyperlinkEvent e) {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                    try {
                        // Open the link in the default browser
                        java.awt.Desktop.getDesktop().browse(e.getURL().toURI());
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });

        JScrollPane helpPane = new JScrollPane(editorPane);
        helpPane.setPreferredSize(new Dimension(500, 250));
        helpPane.setBorder(BorderFactory.createEmptyBorder());

        // help content
        JOptionPane.showMessageDialog(burpFrame, helpPane, "Help Resources", JOptionPane.INFORMATION_MESSAGE);
    
        });

    
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = GridBagConstraints.REMAINDER;
        constraints.gridheight = 1;
        constraints.weightx = 1.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        this.add(footerPanel, constraints);
    }
    
    private String uploadJsonFile() {
        
        final JFileChooser fileChooser = new JFileChooser();

        // accept only .json 
        FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON Files", "json");
        fileChooser.setFileFilter(filter);
        fileChooser.setAcceptAllFileFilterUsed(false);

        
        int returnValue = fileChooser.showOpenDialog(null);

        // Check if a file was selected
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();

            // Check if the file has a .json extension
            if (selectedFile.getName().toLowerCase().endsWith(".json")) {

                // Read the content of the file
                String content;
                try {
                    content = new String(Files.readAllBytes(Paths.get(selectedFile.getPath())));
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(burpFrame, "Error reading the file", "File Error", JOptionPane.ERROR_MESSAGE);
                    logTextArea.insert(getFormattedTime() + " - Error reading the file\n",0);
                    return null;
                }

                // Return the decrypted content
                return content;
            } else {
                JOptionPane.showMessageDialog(burpFrame, "Please select a file with .json extension", "Invalid File", JOptionPane.ERROR_MESSAGE);
                logTextArea.insert(getFormattedTime() + " - Please select a file with .json extension\n",0);
            }
        } else {
            JOptionPane.showMessageDialog(burpFrame, "No file was selected", "Cancelled", JOptionPane.WARNING_MESSAGE);
            logTextArea.insert(getFormattedTime() + " - No file was selected\n",0);
        }

        return null;
    }

    private String currentConfiguration() {

        // Create a list to hold the combined objects
        List<Object> combinedList = new ArrayList<>();

        for (boolean b : http_check) {
            var map = new java.util.HashMap<String, Object>();
            map.put("http_check", b);

            combinedList.add(map);
        }

        for (HttpRequestResponse rr : req_res) {
            var map = new java.util.HashMap<String, Object>();
            map.put("Response", rr.response().toString());
            map.put("Request", rr.request().toString());

            combinedList.add(map);
        }

        for (HttpResponse ec : expired_conditions) {
            var map = new java.util.HashMap<String, Object>();
            map.put("expired_conditions", ec.toString());

            combinedList.add(map);
        }

        for (boolean tc : tools_check) {
            var map = new java.util.HashMap<String, Object>();
            map.put("tools_check", tc);

            combinedList.add(map);
        }

        //Convert the list of combined objects to JSON
        Gson gson = new Gson();
        return gson.toJson(combinedList);

    }

    private void exportJsonFile(String jsonContent) {

        final JFileChooser fileChooser = new JFileChooser();

        // Suggest a default filename
        fileChooser.setSelectedFile(new File("tokenTailor.json"));

        // Set a filter to accept only .json files
        FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON Files", "json");
        fileChooser.setFileFilter(filter);
        fileChooser.setAcceptAllFileFilterUsed(false);

        // Open the save dialog and get the user input
        int returnValue = fileChooser.showSaveDialog(null);

        // Check if the user has selected a file to save
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();

            // Write the content to the file
            try (FileWriter fileWriter = new FileWriter(fileToSave)) {
                fileWriter.write(jsonContent);
                JOptionPane.showMessageDialog(burpFrame, "File was saved successfully!");
                logTextArea.insert(getFormattedTime()+" - File was saved successfully.\n", 0);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(burpFrame, "Error writing the file", "File Error", JOptionPane.ERROR_MESSAGE);
                logTextArea.insert(getFormattedTime()+" - Error writing the file.\n", 0);

            }
        } else {
            JOptionPane.showMessageDialog(burpFrame, "File save cancelled.", "Cancelled", JOptionPane.WARNING_MESSAGE);
            logTextArea.insert(getFormattedTime()+" - File save cancelled.\n", 0);
        }
    }

    private void setNewConfiguration(String content) {
        if (content != null) {
            
            // Parse JSON to check the content format
            Gson gson = new Gson();
            Type listType = new TypeToken<List<Map<String, Object>>>() {}.getType();
            List<Map<String, Object>> dataList;
            
            try {
                dataList = gson.fromJson(content, listType);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(burpFrame, "Invalid JSON format.");
                logTextArea.insert(getFormattedTime()+" - Invalid JSON format.\n", 0);
                return;
            }
    
            // Validate the content structure
            if (!isValidContent(dataList)) {
                JOptionPane.showMessageDialog(burpFrame, "Invalid content structure.");
                logTextArea.insert(getFormattedTime()+" - Invalid content structure\n", 0);
                return;
            }

            List<Boolean> http_check_tmp = new ArrayList<>();
            List<HttpResponse> expired_conditions_tmp = new ArrayList<>();
            List<Boolean> tools_check_tmp = new ArrayList<>();
            List<HttpRequestResponse> req_res_tmp = new ArrayList<>();

            //clear current state
            req_res.clear();
            req_res.add(HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(""), HttpResponse.httpResponse("")));

            http_check.clear();
            http_check.add(false);

            checkboxes_http_check.clear();
            checkboxes_http_check.add(new JToggleButton());

            editor_requests.clear();
            editor_requests.add(montoyaApi.userInterface().createHttpRequestEditor());

            editor_responses.clear();
            editor_responses.add(montoyaApi.userInterface().createHttpResponseEditor());
            
            expired_conditions.clear();
            expired_conditions.add(HttpResponse.httpResponse());
            
            editor_expired_conditions.clear();
            editor_expired_conditions.add(montoyaApi.userInterface().createHttpResponseEditor());         

            importFlow = true;

            for (Map<String, Object> item : dataList) {
                if (item.containsKey("http_check")) {
                    http_check_tmp.add((Boolean) item.get("http_check"));
                } else if (item.containsKey("expired_conditions")) {
                    expired_conditions_tmp.add(HttpResponse.httpResponse((String) item.get("expired_conditions")));
                } else if (item.containsKey("tools_check")) {
                    tools_check_tmp.add((Boolean) item.get("tools_check"));
                } else if (item.containsKey("Request") && item.containsKey("Response")) {
                    HttpRequest req = HttpRequest.httpRequest((String) item.get("Request"));
                    HttpResponse res = HttpResponse.httpResponse((String) item.get("Response"));
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(req, res);
                    req_res_tmp.add(rr);
                }
            }
    
            // Update tools check list
            for (int h = 0; h < tools_check_tmp.size(); h++) {
                if (h < tools_check.size()) {
                    tools_check.set(h, tools_check_tmp.get(h));
                } else {
                    tools_check.add(tools_check_tmp.get(h));
                }
                checkboxes_tools_check.get(h).setSelected(tools_check.get(h));
            }

            //Update Requests and Responses
            while (jTabbedPane3.getTabCount() > 1 ){
                jTabbedPane3.removeTabAt(jTabbedPane3.getTabCount() - 1 );
            }
    
            for (int h = 1; h < req_res_tmp.size(); h++) {
                
                if(req_res.size() <= h){
                    req_res.add(h, req_res_tmp.get(h));
                } else {
                    req_res.set(h, req_res_tmp.get(h));
                }

                if(http_check.size() <= h){
                    http_check.add(h, http_check_tmp.get(h));
                } else {
                    http_check.set(h, http_check.get(h));
                }

                if(checkboxes_http_check.size() <= h){
                    checkboxes_http_check.add(h, new JToggleButton());
                }
                
                checkboxes_http_check.get(h).setSelected(http_check.get(h));

                if(editor_requests.size() <= h){
                    editor_requests.add(h, montoyaApi.userInterface().createHttpRequestEditor());
                } 
                    
                editor_requests.get(h).setRequest(HttpRequest.httpRequest(req_res_tmp.get(h).request().toString()));
                
                if(editor_responses.size() <= h){
                    editor_responses.add(h, montoyaApi.userInterface().createHttpResponseEditor());
                } 
                    
                editor_responses.get(h).setResponse(HttpResponse.httpResponse(req_res_tmp.get(h).response().toString()));

                addReq("Request " + jTabbedPane3.getTabCount(), new JPanel(), jTabbedPane3);

                jTabbedPane3.setSelectedIndex(jTabbedPane3.getTabCount() - 1);

            }

            //Update Expired Conditions
            while (jTabbedPane4.getTabCount() > 1 ){
                jTabbedPane4.removeTabAt(jTabbedPane4.getTabCount() - 1 );
            }
    
            for (int h = 1; h < expired_conditions_tmp.size(); h++) {
                
                if(expired_conditions.size() <= h){
                    expired_conditions.add(h, expired_conditions_tmp.get(h));
                } else {
                    expired_conditions.set(h, expired_conditions_tmp.get(h));
                }

                if(editor_expired_conditions.size() <= h){
                    editor_expired_conditions.add(h, montoyaApi.userInterface().createHttpResponseEditor());
                } 
                    
                editor_expired_conditions.get(h).setResponse(expired_conditions_tmp.get(h));
                
                
                addExp("Expired Condition " + jTabbedPane4.getTabCount(), new JPanel(), jTabbedPane4);

                jTabbedPane4.setSelectedIndex(jTabbedPane4.getTabCount() - 1);        

            }

            importFlow = false;
            this.revalidate();
            this.repaint();
            
        } else {
            JOptionPane.showMessageDialog(burpFrame, "The file is empty");
            logTextArea.insert(getFormattedTime()+" - The file is empty\n", 0);
        }
    }
    
    private boolean isValidContent(List<Map<String, Object>> dataList) {
    Set<String> validKeys = new HashSet<>(Arrays.asList("http_check", "expired_conditions", "tools_check", "Request", "Response"));
    for (Map<String, Object> item : dataList) {
        for (String key : item.keySet()) {
            if (!validKeys.contains(key)) {
                return false;
            }
        }
        if (item.containsKey("http_check") && item.get("http_check") instanceof Boolean) {
            continue;
        } else if (item.containsKey("expired_conditions") && item.get("expired_conditions") instanceof String) {
            continue;
        } else if (item.containsKey("tools_check") && item.get("tools_check") instanceof Boolean) {
            continue;
        } else if (item.containsKey("Request") && item.get("Request") instanceof String
                && item.containsKey("Response") && item.get("Response") instanceof String) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}
    private void activeError(String str) {
        JOptionPane.showMessageDialog(burpFrame, "Error: " + str, "Error", JOptionPane.ERROR_MESSAGE);
        activeState.setText("OFF");
        impExp.setText("IMPORT");
        activeState.setSelected(false);
        logTextArea.insert(getFormattedTime() +" - Error: " + str+"\n", 0);

    }

    private void unselectAllTools(int k) {
        if (allTools.isSelected()) {
            allTools.setSelected(false);
            tools_check.set(0, false);
            tools_check.set(k, true);
        }
    }

    private void selectAllTools() {

        Boolean value = allTools.isSelected();

        tools_check.set(0, value);

        for (int i = 0; i < checkboxList.size(); i++) {
            JCheckBox checkbox = checkboxList.get(i);
            checkbox.setSelected(!value);

            checkboxList.set(i, checkbox);
            tools_check.set(i + 1, !value);
        }
    }

    private void addExp(String title, JPanel component, JTabbedPane mainTabbedPane) {

        mainTabbedPane.addTab(title, component);
        int index = mainTabbedPane.indexOfComponent(component);
        // Create a panel with a label and close button as the tab component
        JPanel tabPanel = new JPanel();
        tabPanel.setOpaque(false);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(new Color(255, 102, 0));

        JButton closeButton = new JButton("x");
        closeButton.setBorder(BorderFactory.createEmptyBorder());
        closeButton.setContentAreaFilled(false);
        closeButton.addActionListener(e -> {
            turnoffTokenTailor();
            rmTab(mainTabbedPane, mainTabbedPane.indexOfComponent(component), "Expired Condition");
        });

        tabPanel.add(titleLabel);
        tabPanel.add(closeButton);

        mainTabbedPane.setTabComponentAt(index, tabPanel);
        mainTabbedPane.setForeground(new java.awt.Color(255, 102, 0));

        JTextPane description = new JTextPane();

        description.setEditable(false);
        description.setAlignmentX(CENTER_ALIGNMENT);
        description.setText("Please provide the exact HTTP responses that are retrieved when an expired condition occurs. These examples should be the complete HTTP responses, including headers and body.\n" + //
                        "\n" +
                        "The delimiters \"§§\" are always used in pairs (an even number) and there may be multiple pairs within a single response. \n" + //
                        "If the delimiters are present, Token Tailor will check if the text contained within each pair of delimiters is also present in the response received.\n" + //
                        "If the delimiters \"§§\" are not included in the examples, the tool will default to using a general error code and payload for comparison purposes.");

        HttpResponseEditor expEditor = montoyaApi.userInterface().createHttpResponseEditor();

        if(expired_conditions.size() == index + 1){
            expEditor.setResponse(expired_conditions.get(index));
            if(expEditor.getResponse().toString().contains("§")){
                expEditor.setSearchExpression("§");
            }

        } else {
            expEditor.setResponse(HttpResponse.httpResponse(""));
            expired_conditions.add(HttpResponse.httpResponse(""));
        }

        Component expComponent = expEditor.uiComponent();

        if(editor_expired_conditions.size() == index + 1){
            editor_expired_conditions.set(index, expEditor);

        } else {
            editor_expired_conditions.add(expEditor);
        }
        addFocusListenerRecursively(expComponent, new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                turnoffTokenTailor();
                expired_conditions.set(mainTabbedPane.indexOfComponent(component), expEditor.getResponse());
            }
        });

        JButton addPar = new JButton("Add §");
        addPar.addActionListener(e -> {

            turnoffTokenTailor();
            ByteArray newRes = ByteArray.byteArrayOfLength(0);
            if (!expEditor.selection().isEmpty()) {

                int startRange = expEditor.selection().get().offsets()
                        .startIndexInclusive();

                int endRange = expEditor.selection().get().offsets().endIndexExclusive();

                Range range = expEditor.selection().get().offsets();
                ByteArray subarray = expEditor.getResponse().toByteArray().subArray(range);

                ByteArray prefix = expEditor.getResponse().toByteArray().subArray(0,
                        startRange);

                // if all the request is selected
                if (!(expEditor.getResponse().toByteArray().length() == endRange)) {
                    ByteArray suffix = expEditor.getResponse().toByteArray().subArray(
                            endRange,
                            expEditor.getResponse().toByteArray().length());

                    newRes = prefix.withAppended('§').withAppended(subarray).withAppended('§')
                            .withAppended(suffix);

                } else {
                    newRes = prefix.withAppended('§').withAppended(subarray).withAppended('§');
                }
                expEditor.setResponse(HttpResponse.httpResponse(newRes));
                expEditor.setSearchExpression("§");

            } else {

                int position = expEditor.caretPosition();
                
                //empty request
                if (expEditor.getResponse().toByteArray().length() == 0) {
                    newRes = ByteArray.byteArray("§");
                } else {
                    ByteArray prefix = expEditor.getResponse().toByteArray().subArray(0,
                            position);

                    // request not empty, nothing selected, position at the end
                    if (expEditor.getResponse().toByteArray().length() == position) {
                        newRes = prefix.withAppended('§');
                    } else {
                        ByteArray suffix = expEditor.getResponse().toByteArray()
                                .subArray(position,
                                        expEditor.getResponse()
                                                .toByteArray()
                                                .length());

                        newRes = prefix.withAppended('§').withAppended(suffix);
                    }

                }
                expEditor.setResponse(HttpResponse.httpResponse(newRes));
                expEditor.setSearchExpression("§");

            }
            expired_conditions.set(index, expEditor.getResponse());

        });

        JButton removePar = new JButton("Remove §");
        removePar.addActionListener(e -> {

            turnoffTokenTailor();
            if (expEditor.getResponse().contains("§", false)) {
                expEditor.setResponse(HttpResponse.httpResponse(expEditor.getResponse().toString().replaceAll("§", "")));
            }
            expired_conditions.set(index, expEditor.getResponse());

        });

        expLayout(component, expComponent, addPar, removePar, description);
    }

    private void expLayout(JPanel component, Component expComponent, JButton addPar, JButton removePar, JTextPane description) {

        component.setLayout(new GridBagLayout());
        GridBagConstraints gbc_exp = new GridBagConstraints();
    
        gbc_exp.gridx = 0;
        gbc_exp.gridy = 0;
        gbc_exp.gridwidth = GridBagConstraints.REMAINDER;
        gbc_exp.gridheight = 1;
        gbc_exp.weightx = 1.0;
        gbc_exp.weighty = 0.05;
        gbc_exp.fill = GridBagConstraints.BOTH;
        component.add(description, gbc_exp);
        gbc_exp.insets = new Insets(5, 5, 5, 5);

    
        gbc_exp.gridx = 0;
        gbc_exp.gridy = 1;
        gbc_exp.gridwidth = 1;
        gbc_exp.gridheight = 1;
        gbc_exp.weightx = 0.5;
        gbc_exp.weighty = 0.05;
        gbc_exp.fill = GridBagConstraints.NONE;
        gbc_exp.anchor = GridBagConstraints.WEST;
        component.add(addPar, gbc_exp);
    
        gbc_exp.gridx = 1;
        gbc_exp.gridy = 1;
        gbc_exp.gridwidth = 1;
        gbc_exp.gridheight = 1;
        gbc_exp.weightx = 0.5;
        gbc_exp.weighty = 0.05;
        gbc_exp.fill = GridBagConstraints.NONE;
        gbc_exp.anchor = GridBagConstraints.EAST;
        component.add(removePar, gbc_exp);
    
        gbc_exp.gridx = 0;
        gbc_exp.gridy = 2;
        gbc_exp.gridwidth = GridBagConstraints.REMAINDER;
        gbc_exp.gridheight = 1;
        gbc_exp.weightx = 1.0;
        gbc_exp.weighty = 0.90;
        gbc_exp.fill = GridBagConstraints.BOTH;
        component.add(expComponent, gbc_exp);
    }
    

    private void addReq(String title, JPanel component, JTabbedPane mainTabbedPane) {

        mainTabbedPane.addTab(title, component);
        int index = mainTabbedPane.indexOfComponent(component);

        JPanel tabPanel = new JPanel();
        tabPanel.setOpaque(false);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(new Color(255, 102, 0));

        JButton closeButton = new JButton("x");
        closeButton.setBorder(BorderFactory.createEmptyBorder());
        closeButton.setContentAreaFilled(false);
        closeButton.addActionListener(e -> {
            turnoffTokenTailor();
            rmTab(mainTabbedPane, mainTabbedPane.indexOfComponent(component), "Request");
        });

        tabPanel.add(titleLabel);
        tabPanel.add(closeButton);

        mainTabbedPane.setTabComponentAt(index, tabPanel);
        mainTabbedPane.setForeground(new java.awt.Color(255, 102, 0));

        JTextPane description_req = new JTextPane();
        description_req.setEditable(false);
        description_req.setFocusable(false);
        description_req.setText("Add the requests required to acquire a new Bearer or Basic authentication token.\n"+" It can be included multiple requests to automate the process.\n"+" The last request should be where the token is obtained.");
        description_req.setBackground(new Color(0, 0, 0, 0));
        description_req.setBackground(new Color(255, 255, 255, 128));
        description_req.setOpaque(false);
        Style style_req = description_req.addStyle("Centered", null);
        description_req.getStyledDocument().setParagraphAttributes(0, description_req.getText().length(), style_req, false);

        JTextPane description_res = new JTextPane();
        description_res.setEditable(false);
        description_res.setFocusable(false);
        description_res.setText("The response panel will automatically select the first bearer token found if no specific token is enclosed between \"§§\". In case of a request flow, it is possible to carry forward elements such as cookies, custom headers, or parts of the response body to the next request. This allows for seamless completion of the entire request flow by maintaining necessary session data and authentication tokens.");
        description_res.setBackground(new Color(0, 0, 0, 0));
        description_res.setBackground(new Color(255, 255, 255, 128));
        description_res.setOpaque(false);
        Style style_res = description_res.addStyle("Centered", null);
        description_res.getStyledDocument().setParagraphAttributes(0, description_req.getText().length(), style_res, false);

        HttpRequestEditor httpRequestEditor = montoyaApi.userInterface().createHttpRequestEditor();
        HttpResponseEditor httpResponseEditor = montoyaApi.userInterface().createHttpResponseEditor();

        if(req_res.size() == index + 1){
            httpRequestEditor.setRequest(req_res.get(index).request());
            if(httpRequestEditor.getRequest().toString().contains("§")){
                httpRequestEditor.setSearchExpression("§");
            }
            httpResponseEditor.setResponse(req_res.get(index).response());
            if(httpResponseEditor.getResponse().toString().contains("§")){
                httpResponseEditor.setSearchExpression("§");
            }
        } else{
            httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
            httpResponseEditor.setResponse(HttpResponse.httpResponse(""));
            req_res.add(HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(""), HttpResponse.httpResponse("")));
        }

        Component requestComponent = httpRequestEditor.uiComponent();
        if(editor_requests.size() == index + 1){
            editor_requests.set(index, httpRequestEditor);
        } else {
            editor_requests.add(httpRequestEditor);
        }

        Component responseComponent = httpResponseEditor.uiComponent();
        if(editor_responses.size() == index + 1){
            editor_responses.set(index, httpResponseEditor);
        } else {
            editor_responses.add(httpResponseEditor);
        }

        JToggleButton httpCheck = new JToggleButton("HTTPS", false);

        if(http_check.size() == index +1){
            httpCheck.setSelected(http_check.get(index));
            httpCheck.setText((httpCheck.isSelected()? "HTTP": "HTTPS"));
            checkboxes_http_check.set(index, httpCheck);
        }else {
            http_check.add(httpCheck.isSelected());
            httpCheck.setText((httpCheck.isSelected()? "HTTP": "HTTPS"));
            checkboxes_http_check.add(httpCheck);
        }

        httpCheck.addActionListener(e -> {
            turnoffTokenTailor();
            httpCheck.setText((httpCheck.isSelected()? "HTTP": "HTTPS"));
            if (http_check.isEmpty())
                http_check.add(true);
            if (index == (http_check.size())) {
                http_check.add(false);
            }
            http_check.set(index, httpCheck.isSelected());
            req_res.set(index, HttpRequestResponse.httpRequestResponse(httpRequestEditor.getRequest(),
                    httpResponseEditor.getResponse()));
        });

        addFocusListenerRecursively(requestComponent, new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                turnoffTokenTailor();
                req_res.set(mainTabbedPane.indexOfComponent(component), HttpRequestResponse.httpRequestResponse(httpRequestEditor.getRequest(), httpResponseEditor.getResponse()));
                http_check.set(mainTabbedPane.indexOfComponent(component), httpCheck.isSelected());
            }
        });
        addFocusListenerRecursively(responseComponent, new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                turnoffTokenTailor();
                req_res.set(mainTabbedPane.indexOfComponent(component), HttpRequestResponse.httpRequestResponse(httpRequestEditor.getRequest(), httpResponseEditor.getResponse()));
                http_check.set(mainTabbedPane.indexOfComponent(component), httpCheck.isSelected());
            }
        });

        JButton addSecRes = new JButton("Add §");
        addSecRes.addActionListener(e -> {

            turnoffTokenTailor();
            ByteArray newReq = ByteArray.byteArrayOfLength(0);
            if (!httpResponseEditor.selection().isEmpty()) {

                int startRange = httpResponseEditor.selection().get().offsets()
                        .startIndexInclusive();

                int endRange = httpResponseEditor.selection().get().offsets().endIndexExclusive();

                Range range = httpResponseEditor.selection().get().offsets();
                ByteArray subarray = httpResponseEditor.getResponse().toByteArray().subArray(range);

                ByteArray prefix = httpResponseEditor.getResponse().toByteArray().subArray(0,
                        startRange);

                if (!(httpResponseEditor.getResponse().toByteArray().length() == endRange)) {
                    ByteArray suffix = httpResponseEditor.getResponse().toByteArray().subArray(
                            endRange,
                            httpResponseEditor.getResponse().toByteArray().length());

                    newReq = prefix.withAppended('§').withAppended(subarray).withAppended('§')
                            .withAppended(suffix);

                } else {
                    newReq = prefix.withAppended('§').withAppended(subarray).withAppended('§');
                }
                httpResponseEditor.setResponse(HttpResponse.httpResponse(newReq));
                httpResponseEditor.setSearchExpression("§");

            } else {

                int position = httpResponseEditor.caretPosition();
                if (httpResponseEditor.getResponse().toByteArray().length() == 0) {
                    newReq = ByteArray.byteArray("§");
                } else {
                    ByteArray prefix = httpResponseEditor.getResponse().toByteArray().subArray(0,
                            position);
                    if (httpResponseEditor.getResponse().toByteArray().length() == position) {
                        newReq = prefix.withAppended('§');
                    } else {
                        ByteArray suffix = httpResponseEditor.getResponse().toByteArray()
                                .subArray(position,
                                        httpResponseEditor.getResponse()
                                                .toByteArray()
                                                .length());

                        newReq = prefix.withAppended('§').withAppended(suffix);
                    }

                }
                httpResponseEditor.setResponse(HttpResponse.httpResponse(newReq));
                httpResponseEditor.setSearchExpression("§");

            }
            req_res.set(index, HttpRequestResponse.httpRequestResponse(httpRequestEditor.getRequest(), httpResponseEditor.getResponse()));
            http_check.set(index, httpCheck.isSelected());

        });

        JButton removeSecRes = new JButton("Remove §");
        removeSecRes.addActionListener(e -> {

            turnoffTokenTailor();
            if (httpResponseEditor.getResponse().contains("§", false)) {
                httpResponseEditor.setResponse(HttpResponse.httpResponse(httpResponseEditor.getResponse().toString().replaceAll("§", "")));
            }
            req_res.set(index, HttpRequestResponse.httpRequestResponse(httpRequestEditor.getRequest(), httpResponseEditor.getResponse()));
            http_check.set(index, httpCheck.isSelected());

        });

        JButton send_btn = new JButton();
        send_btn.setText("Send Request");
        send_btn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {

                turnoffTokenTailor();
                int index = mainTabbedPane.indexOfComponent(component);
                HttpRequest request = httpRequestEditor.getRequest();

                if (index == 1) {
                    if (request.toByteArray().countMatches("§") > 0) {
                        activeError("The Request contains §");
                        return;
                    }
                }
                if (request.toByteArray().countMatches("§") % 2 != 0) {
                    activeError("The number § has to be even");
                    return;
                }
                if (index >= 1) {
                    HttpResponse prevRes = req_res.get(index - 1).response();

                    List<HttpHeader> resHeaders = prevRes.headers();

                    List<HttpHeader> toAdd = new ArrayList<>();

                    for (HttpHeader h : resHeaders) {
                        if (h.value().contains("§")) {
                            long count = h.value().chars().filter(ch -> ch == '§').count();
                            if (count % 2 == 0) {
                                String[] parts = h.value().split("§");

                                if (parts[1].equals("")) {
                                    activeError("There is only one § into the body");
                                    return;
                                } else {
                                    for (int i = 1; i < parts.length; i += 2) {
                                        String value = parts[1];
                                        if (h.name().equals("Set-Cookie")) {
                                            if (isJWT(value)) {
                                                toAdd.add(HttpHeader.httpHeader("Authorization", value));
                                            } else if(isBasicAuth(value)) {
                                                toAdd.add(HttpHeader.httpHeader("Basic", value));
                                            } else{
                                                toAdd.add(HttpHeader.httpHeader("Cookie", value));
                                            }
                                        } else if (isJWT(value)) {
                                            toAdd.add(HttpHeader.httpHeader("Authorization", value));

                                        } else if (isBasicAuth(value)){
                                            toAdd.add(HttpHeader.httpHeader("Basic", value));
                                        } else{
                                            toAdd.add(HttpHeader.httpHeader(h.name(), value));
                                        }
                                    }
                                }

                            } else {
                                activeError("The number of § is not even");
                                return;
                            }
                        }
                    }

                    String bodyRes = prevRes.body().toString();
                    if (bodyRes.contains("§")) {
                        long count = bodyRes.chars().filter(ch -> ch == '§').count();
                        if (count % 2 == 0) {
                            String[] parts = bodyRes.split("§");
                            if (parts[1].equals("")) {
                                activeError("There is only one § into the body");
                                return;
                            } else {
                                for (int i = 1; i < parts.length; i += 2) {
                                        String value = parts[i];
                                        if (isJWT(value)) {
                                            toAdd.add(HttpHeader.httpHeader("Authorization", value));
                                        } else if (isBasicAuth(value)) {
                                            toAdd.add(HttpHeader.httpHeader("Basic", value));
                                        }
                                    }
                                }
                            } else {
                                activeError("The number of § is not even");
                                return;
                            }
                        }
    
                        for (HttpHeader ah : toAdd) {
                            if (request.hasHeader(ah.name())) {
                                if (ah.name().equals("Authorization")) {
                                    request = request.withUpdatedHeader(ah.name(), "Bearer " + ah.value());
                                } else if (ah.name().equals("Cookie")) {
    
                                    String[] cookies = ah.value().split("; ");
                                    Map<String, String> cookiesMap = getCookieName(cookies);
    
                                    String[] reqCookies = request.header("Cookie").value().split("; ");
                                    Map<String, String> reqCookiesMap = getCookieName(reqCookies);
    
                                    StringBuilder updatedHeader = new StringBuilder(" ");
    
                                    for (Map.Entry<String, String> value : cookiesMap.entrySet()) {
                                        reqCookiesMap.put(value.getKey(), value.getValue());
                                    }
    
                                    for (Map.Entry<String, String> value : reqCookiesMap.entrySet()) {
                                        updatedHeader.append(value.getKey()).append("=").append(value.getValue()).append("; ");
                                    }
    
                                    request = request.withUpdatedHeader(ah.name(), updatedHeader.toString());
    
                                } else {
                                    request = request.withUpdatedHeader(ah);
                                }
                            } else {
                                request = request.withAddedHeader(ah);
                            }
                        }
    
                        HttpService userService;

                        String host = request.header("Host").value().split(":")[0];
                        if(request.header("Host").value().split(":").length > 1 ){

                            int port;
                            try {
                                port = Integer.parseInt(request.header("Host").value().split(":")[1]);
                            } catch (Exception e) {
                                JOptionPane.showMessageDialog(burpFrame, e, "The provided port number is invalid", JOptionPane.ERROR_MESSAGE);
                                logTextArea.insert(getFormattedTime()+" - The provided port number is invalid\n", 0);
                                return;
                            }
                            userService = HttpService.httpService(host, port, !httpCheck.isSelected());
                        } else {
                            userService = HttpService.httpService(host, !httpCheck.isSelected());
                        }

                        HttpRequest userRequestHttp = HttpRequest.httpRequest(userService, request.toByteArray());
    
                        if (!userRequestHttp.isInScope()) {
                            JOptionPane.showMessageDialog(burpFrame, "URL not in scope: " + host, "Error", JOptionPane.ERROR_MESSAGE);
                            logTextArea.insert(getFormattedTime()+" - URL not in scope: " + host +"\n", 0);
                            return;
                        } else {
                            SwingWorker<HttpRequestResponse, Void> worker = new SwingWorker<HttpRequestResponse, Void>() {
                                @Override
                                protected HttpRequestResponse doInBackground() throws Exception {
                                    try {
                                        HttpRequestResponse reqRes = montoyaApi.http().sendRequest(userRequestHttp, HttpMode.AUTO);
                                        return reqRes;
                                    } catch (Exception e) {
                                        JOptionPane.showMessageDialog(burpFrame, e, "Error during the request", JOptionPane.ERROR_MESSAGE);
                                        logTextArea.insert(getFormattedTime()+" - Error during the request\n", 0);
                                        return null;
                                    }
                                }
    
                                @Override
                                protected void done() {
                                    try {
                                        HttpRequestResponse reqRes = get();
    
                                        if (reqRes.response().toByteArray().length() == 0)
                                            httpResponseEditor.setResponse(HttpResponse.httpResponse());
                                        else {
                                            httpResponseEditor.setResponse(reqRes.response());
                                            req_res.set(index, HttpRequestResponse.httpRequestResponse(reqRes.request(), reqRes.response()));
                                            http_check.set(index, httpCheck.isSelected());
                                        }
                                    } catch (InterruptedException | ExecutionException e) {
                                        JOptionPane.showMessageDialog(burpFrame, e, "Error showing the response", JOptionPane.ERROR_MESSAGE);
                                        logTextArea.insert(getFormattedTime()+" - Error showing the response\n", 0);
                                    }
                                }
                            };
                            worker.execute();
                        }
                    } else {
                        activeError("Index < 1");
                    }
                }
    
                private Map<String, String> getCookieName(String[] cookies) {
                    Map<String, String> cookiesName = new HashMap<>();
                    for (String c : cookies) {
                        if (c.contains("=")) {
                            String[] name = c.split("=");
                            cookiesName.put(name[0], name[1]);
                        }
                    }
                    return cookiesName;
                }
            });
    
            JButton clearReq_btn = new JButton();
            clearReq_btn.setText("Clear");
            clearReq_btn.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    turnoffTokenTailor();
                    httpRequestEditor.setRequest(HttpRequest.httpRequest());
                    httpResponseEditor.setResponse(HttpResponse.httpResponse());
                    req_res.set(index, HttpRequestResponse.httpRequestResponse(httpRequestEditor.getRequest(), httpResponseEditor.getResponse()));
                    http_check.set(index, httpCheck.isSelected());
                }
            });
    
            addReqLayout(component, description_req, description_res, requestComponent, responseComponent, addSecRes, removeSecRes, httpCheck, send_btn, clearReq_btn);
        }
    
        private void turnoffTokenTailor() {
            if (active_state.get(0)) {
                active_state.set(0, false);
                activeState.setText("OFF");
                activeState.setSelected(false);
                impExp.setText("IMPORT");
                //stopMonitoring();
                logTextArea.insert(getFormattedTime() +" - Token Tailor was turned off\n", 0);
            }
        }
    
        private void addReqLayout(JPanel tabPanel, JTextPane description_req, JTextPane description_res, Component requestComponent, Component responseComponent, JButton addSecRes, JButton removeSecRes, JToggleButton httpCheck, JButton send_btn, JButton clearReq_btn) {
                tabPanel.setLayout(new GridBagLayout());
                GridBagConstraints gbc_req = new GridBagConstraints();
            
                // First row: descriptions
                gbc_req.gridx = 0;
                gbc_req.gridy = 0;
                gbc_req.gridwidth = 1;
                gbc_req.gridheight = 1;
                gbc_req.weightx = 0.5;
                gbc_req.weighty = 0.05;
                gbc_req.fill = GridBagConstraints.BOTH;
                gbc_req.insets = new Insets(5, 5, 5, 5);
                tabPanel.add(description_req, gbc_req);
            
                gbc_req.gridx = 1;
                gbc_req.gridy = 0;
                gbc_req.gridwidth = 1;
                gbc_req.gridheight = 1;
                gbc_req.weightx = 0.5;
                gbc_req.weighty = 0.05;
                gbc_req.fill = GridBagConstraints.BOTH;
                tabPanel.add(description_res, gbc_req);
            
                // Second row: buttons
                gbc_req.gridx = 0;
                gbc_req.gridy = 1;
                gbc_req.gridwidth = 2;
                gbc_req.gridheight = 1;
                gbc_req.weightx = 1.0;
                gbc_req.weighty = 0.05;
                gbc_req.fill = GridBagConstraints.HORIZONTAL;
                JPanel buttonPanel = new JPanel(new GridBagLayout());
                tabPanel.add(buttonPanel, gbc_req);
            
                GridBagConstraints gbc_buttonPanel = new GridBagConstraints();
                gbc_buttonPanel.insets = new Insets(5, 5, 5, 5);
            
                // Add send button and httpCheck to the left
                gbc_buttonPanel.gridx = 0;
                gbc_buttonPanel.gridy = 0;
                gbc_buttonPanel.anchor = GridBagConstraints.WEST;
                buttonPanel.add(send_btn, gbc_buttonPanel);
            
                gbc_buttonPanel.gridx = 1;
                buttonPanel.add(httpCheck, gbc_buttonPanel);
            
                // Add a spacer panel to push the right buttons to the far right
                gbc_buttonPanel.gridx = 2;
                gbc_buttonPanel.weightx = 1.0;
                buttonPanel.add(new JPanel(), gbc_buttonPanel);
            
                // Add addSecRes, removeSecRes, and clearReq_btn to the right
                gbc_buttonPanel.gridx = 3;
                gbc_buttonPanel.weightx = 0;
                gbc_buttonPanel.anchor = GridBagConstraints.EAST;
                buttonPanel.add(addSecRes, gbc_buttonPanel);
            
                gbc_buttonPanel.gridx = 4;
                buttonPanel.add(removeSecRes, gbc_buttonPanel);
            
                gbc_buttonPanel.gridx = 5;
                buttonPanel.add(clearReq_btn, gbc_buttonPanel);
            
                // Third row: components
                gbc_req.gridx = 0;
                gbc_req.gridy = 2;
                gbc_req.gridwidth = 1;
                gbc_req.gridheight = 1;
                gbc_req.weightx = 0.5;
                gbc_req.weighty = 0.90;
                gbc_req.fill = GridBagConstraints.BOTH;
                tabPanel.add(requestComponent, gbc_req);
            
                gbc_req.gridx = 1;
                tabPanel.add(responseComponent, gbc_req);
            }
    
        private void rmTab(JTabbedPane mainTabbedPane, int indexToRemove, String prefix) {
            if (indexToRemove > 0) {
                mainTabbedPane.removeTabAt(indexToRemove);
                for (int i = indexToRemove; i < mainTabbedPane.getTabCount(); i++) {
                    if (i >= 1) {
                        String newTitle = prefix + " " + i;
                        JPanel panel = (JPanel) mainTabbedPane.getTabComponentAt(i);
                        if (panel != null) {
                            for (Component c : panel.getComponents()) {
                                if (c instanceof JLabel) {
                                    JLabel label = (JLabel) c;
                                    if (shouldEditLabel(label.getText(), prefix)) {
                                        label.setText(newTitle);
                                    }
                                }
                                if (c instanceof Component) {
                                    c.toString();
                                }
                            }
                        }
                    }
                }
                if (prefix.equals("Request")) {
                    updateReqRes(indexToRemove);
                    //BUG PERSISTED LIST
                    //updateReqRes(indexToRemove, mainTabbedPane.getTabCount());

                } else if (prefix.equals("Expired Condition")) {
                    updateExpCond(indexToRemove);
                    //BUG PERSISTED LIST
                    //updateExpCond(indexToRemove, mainTabbedPane.getTabCount());
                }
            }
        }
    
        private void updateReqRes (int index){
            
            req_res.remove(index);
            http_check.remove(index);
            editor_requests.remove(index);
            editor_responses.remove(index);
        }
    
        private void updateExpCond(int index) {

            expired_conditions.remove(index);
            editor_expired_conditions.remove(index);
        }
    
        private boolean shouldEditLabel(String text, String prefix) {
            return text.startsWith(prefix + " ");
        }
    
        private void addFocusListenerRecursively(Component component, FocusAdapter focusAdapter) {
            component.addFocusListener(focusAdapter);
            if (component instanceof Container) {
                for (Component child : ((Container) component).getComponents()) {
                    addFocusListenerRecursively(child, focusAdapter);
                }
            }
        }
    
        private boolean isJWT(String value) {
            String jwtRegex = "\\b(eyJ[A-Za-z0-9-_]+)\\.(eyJ[A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\b";
            Pattern pattern = Pattern.compile(jwtRegex);
            Matcher matcher = pattern.matcher(value);
            return matcher.matches();
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

        private String toUpperCamelCase(String input) {

            String[] words = input.split("_");
            StringBuilder result = new StringBuilder();
            
            for (String word : words) {
                // Convert the first character to uppercase and the rest to lowercase
                result.append(word.charAt(0))
                      .append(word.substring(1).toLowerCase())
                      .append(" ");
            }
            
            return result.toString().trim();
        }

        private String getFormattedTime() {
            return "["+LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss"))+"]";
        }

        // Variables declaration - do not modify
        private JButton impExp;
        private JToggleButton activeState;
        private JLabel title;
        private JTabbedPane jTabbedPane2;
        private JPanel jPanel1;
        private JPanel jPanel8;
        private JTabbedPane jTabbedPane3;
        private JPanel jPanel9;
        private JTabbedPane jTabbedPane4;
        private JButton jButton4;
        private JPanel jPanel4;
        private JCheckBox allTools;
        private JPanel jPanel6;
        private JScrollPane jScrollPane7;
        private JTextArea logTextArea;
        private JLabel jLabel7;
        private JScrollPane jScrollPane9;
        private JPanel jPanel3;
        private List<JCheckBox> checkboxList;

    }