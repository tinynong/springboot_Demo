package com.xiaour.spring.boot.utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {
	
    public static String getJsonString(Object javaObj) throws JsonProcessingException {
        String ret = "{}";
        
        ObjectMapper mapper = new ObjectMapper();

        ret = mapper.writeValueAsString(javaObj);

		return ret.replaceAll(":null",":\"\"");

    }

    public static <T> T readJson2Obj(String json, Class<T> classObj) throws JsonParseException,JsonMappingException,IOException  {
        T ret = null;
        
        ObjectMapper mapper = new ObjectMapper();
        
        ret = mapper.readValue(json, classObj);
        
        return ret;
    }

    public static <T> T[] readJson2Array(String json, Class<T[]> classObj) throws JsonParseException,JsonMappingException,IOException   {
        T[] ret = null;
        
        ObjectMapper mapper = new ObjectMapper();

        ret = mapper.readValue(json, classObj);

        return ret;
    }
    
    public static void main(String [] args){                                                                                                                                                                                                                                                                                                                                              
    	Map<String,Object> map= new HashMap<>();
    	map.put("name","xiaochouyu");
    	map.put("stak","小丑鱼");
    	try {
			System.out.println(getJsonString(map));
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
    }

}