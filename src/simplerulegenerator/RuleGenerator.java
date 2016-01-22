/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simplerulegenerator;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author HP
 */
public class RuleGenerator {
    
    //Singleton class
    private static RuleGenerator singleton;
    private static long sid;
    
    private String whiteListDirectory = "whitelisted.txt";
    private ArrayList<String> listWhiteListedHttpMethod;
    
    public static RuleGenerator getSingleton() throws FileNotFoundException{
        if(singleton == null)
            singleton = new RuleGenerator();
        return singleton;
    }
    
    public RuleGenerator() throws FileNotFoundException{
        listWhiteListedHttpMethod = readWhiteListedWords();
        sid = 6000000;
    }
    
    private ArrayList<String> readWhiteListedWords() throws FileNotFoundException{
        ArrayList<String> listWhiteListed = new ArrayList<>();
        
        Scanner sc = null;
        sc = new Scanner(new File(whiteListDirectory));
        
        while(sc.hasNextLine()){
            listWhiteListed.add(sc.nextLine());
        }
        
        return listWhiteListed;
    }
    
    public ArrayList<String> createHttpRule(ArrayList<String> logInboundHttp) throws FileNotFoundException{
        ArrayList<HttpRule> listHttpRule;
        
        ArrayList<String> listSnortRule = new ArrayList<>();
        
        ArrayList<String> log = (ArrayList<String>)logInboundHttp.clone();
        listHttpRule = processLog(logInboundHttp);
        
        for(HttpRule httpRule : listHttpRule){
            listSnortRule.addAll(httpRule.generateSnortRule());
        }
        
//        for(String snortRule : listSnortRule){
//            System.out.println(snortRule);
//        }
        
        return listSnortRule;
    }
    
    //Function for cleansing Log with invalid http syntax
    public ArrayList<HttpRule> processLog(ArrayList<String> logs){
        ArrayList<HttpRule> listHttpRule = new ArrayList<>();
        
        for(String log : logs){
            Pattern p = Pattern.compile("(.+) (.+) (HTTP.*)");
            Matcher m = p.matcher(log);
            if(m.find()){
                //Bikin httpRule
                HttpRule httpRule = new HttpRule();
                httpRule.setMethod(m.group(1));
                httpRule.setUri(m.group(2));
                listHttpRule.add(httpRule);
            }
        }
        return listHttpRule;
    }
    
     public boolean isHttp(int port){
        return port == 80;
    }

    /**
     * @return the listWhiteListedHttpMethod
     */
    public ArrayList<String> getListWhiteListedHttpMethod() {
        return listWhiteListedHttpMethod;
    }
    
    public long generateSid(){
        return sid++;
    }
}
