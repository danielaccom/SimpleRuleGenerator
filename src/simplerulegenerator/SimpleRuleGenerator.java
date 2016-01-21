/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simplerulegenerator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author HP
 */
public class SimpleRuleGenerator {
    
    public static int minLCSLength = 10;

    public static void firstTest() throws FileNotFoundException{
        // TODO code application logic here
        ArrayList<String> listLog = new ArrayList<>();
        ArrayList<String> listPattern = new ArrayList<>();
        ArrayList<String> listRule = new ArrayList<>();
        
        //Read processed log file and search pattern
        Scanner sc = new Scanner(new File("processed_log.txt"));
        
        while(sc.hasNextLine()){
            listLog.add(sc.nextLine());
        }
        
        for(int i = 0;i<listLog.size()-1;i++){
            for(int j = i+1;j<listLog.size();j++){
                //Add kalau belum ada, agar tidak duplikat
                String lcsWord = LCS.longestSubstring(listLog.get(i), listLog.get(j));
                if(!listPattern.contains(lcsWord)){
                    listPattern.add(lcsWord);
                }
            }
        }
        
        //Create Snort rule, still only smb for this rule and write to file
        long sid = 6000000;
        for(String pattern : listPattern){
            String snortRule = "alert tcp $EXTERNAL_NET any -> $HOME_NET 445 "
                    + "("
                    + "msg: \"alert pattern " + pattern + "\";"
                    + "content: \"" + pattern + "\";"
                    + "sid: " + sid++ + ";"
                    + ")";
            listRule.add(snortRule);
        }
        
        //Print to file
        Writer writer = null;

        try {
            writer = new BufferedWriter(new OutputStreamWriter(
                  new FileOutputStream("generated_rule.txt"), "utf-8"));
            for(String rule : listRule){
                writer.write(rule+"\n");
            }
        } catch (IOException ex) {
          // report
        } finally {
           try {writer.close();} catch (Exception ex) {/*ignore*/}
        }
    }
    
    public static void secondTest() throws FileNotFoundException, IOException{
        //List all files
        File folderToScan = new File("net_logs");
        File[] listFile = folderToScan.listFiles();
        HashMap<Integer,ArrayList<String>> hMapLog = new HashMap<>();//Hash map of log
        HashMap<Integer,ArrayList<String>> hMapPattern = null;//Hash map of pattern
        ArrayList<String> listRule = new ArrayList<>();
        
        //Add log to hmap
        //File file = listFile[1];
        for(File file : listFile){
            String contentFile = new String(Files.readAllBytes(Paths.get(file.toString())),StandardCharsets.UTF_8);

            Integer port = Integer.parseInt(file.toString().split("-")[1]);

            DionaeaLogProcessor.getInVertical(hMapLog,port,contentFile);
        }
        
        //Detect pattern of log
        hMapPattern = new HashMap<>();
        Iterator<Integer> keySetIterator = hMapLog.keySet().iterator();
        while(keySetIterator.hasNext()){
            Integer key = keySetIterator.next();
            
            //Search pattern from each protocol
            ArrayList<String> listPattern = new ArrayList<>();
            ArrayList<String> listLog = hMapLog.get(key);
            
            for(int i = 0;i<listLog.size()-1;i++){
                for(int j = i+1;j<listLog.size();j++){
                    //Add kalau belum ada, agar tidak duplikat
                    String lcsWord = LCS.longestSubstring(listLog.get(i), listLog.get(j));
                    if(!listPattern.contains(lcsWord) && lcsWord.length() >= minLCSLength){
                        listPattern.add(lcsWord);
                    }
                }
            }
            
            //Add to hashMap of pattern
            hMapPattern.put(key, listPattern);
        }
        
        //Create Snort rule
        long sid = 6000000;
        keySetIterator = hMapPattern.keySet().iterator();
        while(keySetIterator.hasNext()){
            Integer key = keySetIterator.next();
            ArrayList<String> listPattern = hMapPattern.get(key);
            
            for(String pattern : listPattern){
                String snortRule = "alert tcp $EXTERNAL_NET any -> $HOME_NET "
                        + key + " "
                        + "("
                        + "msg: \"alert pattern " + pattern + "\";"
                        + "content: \"" + pattern + "\";"
                        + "sid: " + sid++ + ";"
                        + ")";
                listRule.add(snortRule);
            }
        }
        
        //Print to file
        Writer writer = null;

        try {
            writer = new BufferedWriter(new OutputStreamWriter(
                  new FileOutputStream("generated_rule_v2.txt"), "utf-8"));
            for(String rule : listRule){
                writer.write(rule+"\n");
            }
        } catch (IOException ex) {
          // report
        } finally {
           try {writer.close();} catch (Exception ex) {/*ignore*/}
        }
        
        return;
    }
    
    public static void testGronland() throws IOException{
        //Gronland variables
        int minLcs = 10;

        //List all files
        File folderToScan = new File("net_logs");
        File[] listFile = folderToScan.listFiles();
        HashMap<Integer,ArrayList<String>> hMapLog = new HashMap<>();//Hash map of log
        HashMap<Integer,ArrayList<String>> hMapPattern = new HashMap<>();//Hash map of pattern with key command
        ArrayList<String> listRule = new ArrayList<>();
        
        //Add log to hmap
        //File file = listFile[1];
        for(File file : listFile){
            String contentFile = new String(Files.readAllBytes(Paths.get(file.toString())),StandardCharsets.UTF_8);

            Integer port = Integer.parseInt(file.toString().split("-")[1]);

            DionaeaLogProcessor.getInVertical(hMapLog,port,contentFile);
        }
        
        //Preprocess log
        Iterator<Integer> keySetIterator = hMapLog.keySet().iterator();
        while(keySetIterator.hasNext()){
            Integer key = keySetIterator.next();
            if(isHttp(key)){
                for(int i = 0;i<hMapLog.get(key).size();i++){
                    String beforeLineBreak = hMapLog.get(key).get(i).substring(0,hMapLog.get(key).get(i).indexOf("\\x0d"));
                    beforeLineBreak = beforeLineBreak.trim();
                    hMapLog.get(key).set(i, beforeLineBreak);
                }
                /*for(String log : hMapLog.get(key)){
                    System.out.println(log);
                }*/
                hMapLog.get(key).sort(null);
            }
        }
        
        //LCS to reduce rule and add pattern
//        keySetIterator = hMapLog.keySet().iterator();
//        while(keySetIterator.hasNext()){
//            Integer key = keySetIterator.next();
//            
//            //Search pattern from each protocol
//            ArrayList<String> listPattern = new ArrayList<>();
//            ArrayList<String> listLog = hMapLog.get(key);
//            
//            if(isHttp(key)){
//                for(String log : listLog){
//                    //Cari duplikat kalau udah ada atau lcsnya melebihi batas dan perintah sama lewat
//                    boolean duplicate = false;
//                    for(String pattern : listPattern){
//                        String[] splitSpaceLog = log.split(" ",2);
//                        String[] splitSpacePattern = pattern.split(" ",2);
//                        if(log.equals(pattern) || splitSpaceLog[0].equals(splitSpacePattern[0]) && LCS.longestSubstring(log, pattern).length() > minLcs){
//                            duplicate = true;
//                        }
//                    }
//                    if(!duplicate)
//                        //String kosong, asumsi sudah dihandle webserver
//                        if(log.length() > 0){
//                            listPattern.add(log);
//                        }
//                }
//            }else{
//                for(String pattern : listLog){
//                    listPattern.add(pattern);
//                }
//            }
//            int i = 1;
//            for(String pattern : listPattern){
//                System.out.println( i++ +" " + pattern);
//            }
//            
//            //Add to hashMap of pattern
//            hMapPattern.put(key, listPattern);
//        }
//        
//        //Create Snort rule
//        long sid = 6000000;
//        keySetIterator = hMapPattern.keySet().iterator();
//        while(keySetIterator.hasNext()){
//            Integer key = keySetIterator.next();
//            ArrayList<String> listPattern = hMapPattern.get(key);
//            
//            
//            if(isHttp(key)){
//                String cont = null;
//                String cont2 = null;
//                String contOrUri = null;
//                int oneOrTwo = 1;
//                //Untuk handle uricontent tidak dobel
//                ArrayList<String> uriContentList = new ArrayList<>();
//                
//                for(String pattern : listPattern){
//                    
//                    if(!pattern.contains("../") && !pattern.contains("%2e%2e") && !pattern.contains("..") && !pattern.contains("./")){
//                        contOrUri = "uricontent";
//                        String[] uri = pattern.split(" ");
//                        if(uri.length>1){
//                            cont = uri[1];
//                        }else{
//                            cont = uri[0];
//                        }
//                    }else{
//                        contOrUri = "content";
//                        
//                    }
//                    
//                    String snortRuleHttp = null;
//                    
//                    if(oneOrTwo == 1){
//                        if(!uriContentList.contains(cont)){
//                            snortRuleHttp = "alert tcp $EXTERNAL_NET any -> $HOME_NET "
//                                + key + " "
//                                + "("
//                                + "msg: \"alert pattern " + sid + "\";"
//                                + contOrUri + " : \"" + cont + "\";"
//                                + "sid: " + sid++ + ";"
//                                + ")";
//                            uriContentList.add(cont);
//                            listRule.add(snortRuleHttp);
//                        }
//                    }/*else{
//                        snortRuleHttp = "alert tcp $EXTERNAL_NET any -> $HOME_NET "
//                            + key + " "
//                            + "("
//                            + "msg: \"alert pattern " + sid + "\";"
//                            + "content: \"" + pattern + "\";"
//                            + "sid: " + sid++ + ";"
//                            + ")";
//                        listRule.add(snortRuleHttp);
//                    }*/
//                    
//                    
//                }
//            }else{//Rule selain http
//                for(String pattern : listPattern){
//                    String snortRule = "alert tcp $EXTERNAL_NET any -> $HOME_NET "
//                            + key + " "
//                            + "("
//                            + "msg: \"alert pattern " + sid + "\";"
//                            + "content: \"" + pattern + "\";"
//                            + "sid: " + sid++ + ";"
//                            + ")";
//                    listRule.add(snortRule);
//                }
//            }
//        }
//        for(String rule : listRule){
//            System.out.println(rule);
//        }
//        
//        //Print to file
//        Writer writer = null;
//
//        try {
//            writer = new BufferedWriter(new OutputStreamWriter(
//                  new FileOutputStream("generated_rule_v2.txt"), "utf-8"));
//            for(String rule : listRule){
//                writer.write(rule+"\n");
//            }
//        } catch (IOException ex) {
//          // report
//        } finally {
//           try {writer.close();} catch (Exception ex) {}
//        }
    }
    
    public static boolean isHttp(int port){
        return port == 80;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, IOException {
        testGronland();
    }
    
}
