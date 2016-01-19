/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simplerulegenerator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author HP
 */
public class DionaeaLogProcessor {
    public static void getInVertical(HashMap<Integer,ArrayList<String>> hMapLog,Integer port,String logString){
        
        //Check message in pattern
        Pattern p = Pattern.compile("\\('in', b'(.+)'\\)");
        Matcher m = p.matcher(logString);
        
        //Add to hMapLog
        while(m.find()){
            //System.out.println(m.group(1));
            ArrayList<String> listLog = hMapLog.get(port);
            
            //Check if empty
            if(listLog == null){
                listLog = new ArrayList<>();
                hMapLog.put(port, listLog);
            }
            listLog.add(m.group(1));
        }
        
    }
}
