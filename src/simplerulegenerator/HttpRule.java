/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simplerulegenerator;

import java.io.FileNotFoundException;
import java.util.ArrayList;

/**
 *
 * @author HP
 */
public class HttpRule {
    
    private String method;
    private String uri;
    private String headers;
    private String body;
    
    public ArrayList<String> generateSnortRule() throws FileNotFoundException{
        ArrayList<String> listSnortRule = new ArrayList<String>();
        Long sid = RuleGenerator.getSingleton().generateSid();
        
        if(isWhiteListedMethod(method)){
            String uriContent = null;
            String[] splittedSlash = uri.split("/");
            if(splittedSlash.length>0){
                String uriContentWithParams = splittedSlash[splittedSlash.length-1];
                
                //Ekstraksi params dan uricontent
                String[] splittedQuestionMark = uriContentWithParams.split("\\?");
                if(splittedQuestionMark.length>1){
                    ArrayList<String> listParam = new ArrayList<>();
                    String[] splittedAndMark = splittedQuestionMark[1].split("&");
                    if(splittedAndMark.length > 1){//Lebih dari 1 params
                        for(int i= 0; i < splittedAndMark.length;i++){
                            listParam.add(splittedAndMark[i].split("=")[0]);
                        }
                    }else{
                        listParam.add(splittedQuestionMark[1].split("=")[0]);
                    }
                    
                    uriContent = splittedQuestionMark[0];
                    
                    for(String param : listParam){
                        listSnortRule.add(
                            "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 "
                            + "("
                            + "msg: \"Alert uricontent with params sid " + sid + "\";"
                            + "uricontent: \"" + uriContent + "\";"
                            + "content: \"" + param + "\""
                            + "nocase;"
                            + "sid: " + sid + ";"
                            + ")"
                        );
                    }
                    
                }else{
                    //Just uri content in uriContentWithParams
                    uriContent = uriContentWithParams;
                    listSnortRule.add(
                        "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 "
                        + "("
                        + "msg: \"Alert uricontent sid " + sid + "\";"
                        + "uricontent: \"" + uriContentWithParams + "\";"
                        + "nocase;"
                        + "sid: " + sid + ";"
                        + ")"
                    );
                }
                
            }
            
        }else{
            listSnortRule.add(
                "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 "
                + "("
                + "msg: \"Alert illegal method sid " + sid + "\";"
                + "content: \"" + method + "\";"
                + "nocase;"
                + "sid: " + sid + ";"
                + ")"
            );
        }
        return listSnortRule;
    }
    
    public boolean isWhiteListedMethod(String method) throws FileNotFoundException{
        for(String whiteListedMethod : RuleGenerator.getSingleton().getListWhiteListedHttpMethod()){
            if(method.equals(whiteListedMethod)){
                return true;
            }
        }
        return false;
    }
    
    @Override
    public String toString(){
        return method + " " + uri + " " + headers + " " + body;
    }

    /**
     * @param method the method to set
     */
    public void setMethod(String method) {
        this.method = method;
    }

    /**
     * @param uri the uri to set
     */
    public void setUri(String uri) {
        this.uri = uri;
    }

    /**
     * @param headers the headers to set
     */
    public void setHeaders(String headers) {
        this.headers = headers;
    }

    /**
     * @param body the body to set
     */
    public void setBody(String body) {
        this.body = body;
    }
    
}
