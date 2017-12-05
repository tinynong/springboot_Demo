package com.xiaour.spring.boot.config;

import java.sql.SQLException;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.alibaba.druid.pool.DruidDataSource;

@Configuration
@EnableTransactionManagement
public class DataBaseConfiguration implements EnvironmentAware {

	private RelaxedPropertyResolver propertyResolver;

	private static Logger log = LoggerFactory.getLogger(DataBaseConfiguration.class);


	/**
	 * 初始化yml配置
	 */
	@Override
	public void setEnvironment(Environment env) {
		this.propertyResolver = new RelaxedPropertyResolver(env, "jdbc.datasource.");
	}

	/**
	 * 配置数据源
	 * @return
	 */
	@Bean(name = "dataSource",destroyMethod = "close")
	public DataSource dataSource() {
         
         DruidDataSource dataSource = new DruidDataSource();  
         dataSource.setUrl(propertyResolver.getProperty("url"));  
         dataSource.setUsername(propertyResolver.getProperty("username"));//用户名  
         dataSource.setPassword(propertyResolver.getProperty("password"));//密码  
         dataSource.setDriverClassName(propertyResolver.getProperty("driver-class-name")); 
         dataSource.setInitialSize(Integer.parseInt(propertyResolver.getProperty("initialSize")));  
         dataSource.setMaxActive(Integer.parseInt(propertyResolver.getProperty("maxActive")));  
         dataSource.setMinIdle(Integer.parseInt(propertyResolver.getProperty("minIdle")));  
         dataSource.setMaxWait(Integer.parseInt(propertyResolver.getProperty("maxWait")));  
         dataSource.setTimeBetweenEvictionRunsMillis(Integer.parseInt(propertyResolver.getProperty("timeBetweenEvictionRunsMillis")));  
         dataSource.setMinEvictableIdleTimeMillis(Integer.parseInt(propertyResolver.getProperty("minEvictableIdleTimeMillis")));  
         dataSource.setValidationQuery(propertyResolver.getProperty("validationQuery"));  
         dataSource.setTestOnBorrow(Boolean.getBoolean(propertyResolver.getProperty("testOnBorrow")));  
         dataSource.setTestWhileIdle(Boolean.getBoolean(propertyResolver.getProperty("testWhileIdle")));  
         dataSource.setTestOnReturn(Boolean.getBoolean(propertyResolver.getProperty("testOnReturn")));  
         dataSource.setPoolPreparedStatements(Boolean.getBoolean(propertyResolver.getProperty("poolPreparedStatements")));  
         dataSource.setMaxPoolPreparedStatementPerConnectionSize(Integer.parseInt(propertyResolver.getProperty("maxOpenPreparedStatements")));
         try {
        	 //开启druid监控
            dataSource.setFilters("stat,wall");
			dataSource.init();
		} catch (SQLException e) {
			log.error(e.getMessage());
		}
         return dataSource; 
	}

}
