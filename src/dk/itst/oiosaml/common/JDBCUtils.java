package dk.itst.oiosaml.common;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import com.mchange.v2.c3p0.ComboPooledDataSource;

public class JDBCUtils {

	private static DataSource dataSource = null;
	
	static{
		dataSource = new ComboPooledDataSource("txy");
	}
	
	public static Connection getConnection(){  
		try {
			return dataSource.getConnection();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new DBException("数据库连接错误");
		}
	}
 
	public static void release(Connection connection) {
		try {
			if(connection != null){
				connection.close();
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new DBException("数据库连接错误");
		}
	}
	
	public static void release(Connection connection, Statement statement, ResultSet resultSet) {
		try {
			if(resultSet != null){
				resultSet.close();
			}
			if(statement != null){
				statement.close();
			}
			if(connection != null){
				connection.close();
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new DBException("数据库连接错误");
		}
	}
	
}
