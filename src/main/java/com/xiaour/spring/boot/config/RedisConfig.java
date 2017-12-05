package com.xiaour.spring.boot.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

/**
 * 配置redis数据源
 * Java Lib For OIS, Powered By xiaour.
 * @ClassName RedisConfig
 * @author Zhang.Tao
 * @Date 2017年4月24日 下午5:25:30
 * @version V2.0.0
 */
@Configuration
public class RedisConfig {
	private static Logger log = LoggerFactory.getLogger(RedisConfig.class);

    
  @Bean(name= "jedis.pool")  
  @Autowired  
  public JedisPool jedisPool(@Qualifier("jedis.pool.config") JedisPoolConfig config,   
              @Value("${jedis.pool.host}")String host,   
              @Value("${jedis.pool.port}")int port) {  
      return new JedisPool(config, host, port);  
  }  
    
  @Bean(name= "jedis.pool.config")  
  public JedisPoolConfig jedisPoolConfig (@Value("${jedis.pool.config.maxTotal}")int maxTotal,  
                              @Value("${jedis.pool.config.maxIdle}")int maxIdle,  
                              @Value("${jedis.pool.config.maxWaitMillis}")int maxWaitMillis) {  
      try {
		JedisPoolConfig config = new JedisPoolConfig();  
		  config.setMaxTotal(maxTotal);  
		  config.setMaxIdle(maxIdle);  
		  config.setMaxWaitMillis(maxWaitMillis);  
		  return config;
		} catch (Exception e) {
			log.error(e.getMessage());
		}
	return null;  
  } 

}
