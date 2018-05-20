package dk.itst.oiosaml.common;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import com.mchange.v2.c3p0.ComboPooledDataSource;

public class JDBCUtils {
	
	private JDBCUtils() {};

	private static volatile DataSource dataSourceFirst = null;
	private static volatile DataSource dataSourceSecond = null;
	private static volatile DataSource dataSourceAll = null;
	
	public static Connection getConnectionFirst(){
		try {
			if (null == dataSourceFirst) {
				synchronized (JDBCUtils.class) {
					if (null == dataSourceFirst) {
						dataSourceFirst = new ComboPooledDataSource("first");
					}
				}
			}
			return dataSourceFirst.getConnection();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new DBException("数据库连接错误");
		}
	}
	
	public static Connection getConnectionSecond(){
		try {
			if (null == dataSourceSecond) {
				synchronized (JDBCUtils.class) {
					if (null == dataSourceSecond) {
						dataSourceSecond = new ComboPooledDataSource("second");
					}
				}
			}
			return dataSourceSecond.getConnection();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new DBException("数据库连接错误");
		}
	}
	
	public static Connection getConnectionAll(){
		try {
			if (null == dataSourceAll) {
				synchronized (JDBCUtils.class) {
					if (null == dataSourceAll) {
						dataSourceAll = new ComboPooledDataSource("all");
					}
				}
			}
			return dataSourceAll.getConnection();
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
