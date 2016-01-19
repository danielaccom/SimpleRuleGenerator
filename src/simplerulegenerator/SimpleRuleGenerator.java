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
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, IOException {
        secondTest();
    }
    
}
