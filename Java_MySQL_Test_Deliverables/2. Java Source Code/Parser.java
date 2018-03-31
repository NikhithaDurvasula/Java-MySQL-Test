package com.ef;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Parameters(separators = "=")
public class Parser {
  private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

  @Parameter(names = {"--startDate"}, required = true)
  private static String startDateString;

  @Parameter(names = {"--duration"}, required = true)
  private static String duration;

  @Parameter(names = {"--threshold"}, required = true)
  private static Integer threshold;

  @Parameter(names = {"--accesslog"}, required = true)
  private static String accesslog;

  private static Date startDate;
  private static Date endDate;
  private static Connection databaseConnection;


  public void initializeDataBase() throws SQLException, ClassNotFoundException {
    databaseConnection = DriverManager.getConnection("jdbc:mysql://localhost:" + Constants.DB_PORT, Constants.DB_USER, Constants.DB_PASSWD);

    //create the database and switch
    databaseConnection.createStatement().executeUpdate("CREATE DATABASE IF NOT EXISTS " + Constants.DB_SCHEMA);
    databaseConnection.createStatement().executeUpdate("use " + Constants.DB_SCHEMA);

    String createLogDataTableStatement = "CREATE TABLE IF NOT EXISTS LOG_DATA " +
        "(log_date DATETIME(2), " +
        "ip_address VARCHAR(20), " +
        "request VARCHAR(20)," +
        "status INTEGER, " +
        "user_agent VARCHAR(500));";

    String createIpAddressessExceedingLimitTableStatement = "CREATE TABLE IF NOT EXISTS EXCESS_REQUESTS " +
        "(ip_address VARCHAR(20), comments VARCHAR(255));";

    //System.out.println("Creating Log table and Excess Ip table if not exists in the schema");
    databaseConnection.createStatement().executeUpdate(createLogDataTableStatement);
    databaseConnection.createStatement().executeUpdate(createIpAddressessExceedingLimitTableStatement);
  }

  public static void main(String args[]) throws IOException, SQLException, ParseException {
    Parser parser = new Parser();

    //read the arguments
    JCommander.newBuilder()
        .addObject(parser)
        .build()
        .parse(args);

    try {
      parser.initializeDataBase();
      System.out.println("Database connection established");
    } catch (ClassNotFoundException e) {
      System.out.println("No Database Driver Found " + e.getMessage());
      System.exit(1);
    } catch (SQLException e) {
      System.out.println("SQL Exception " + e.getMessage());
      System.exit(1);
    }

    parser.parseStartDateAndComputeEndDate();

    //parse the file and process the log lines
    parser.parseFileAndProcessLogLines();

    //Database Connection closed
    databaseConnection.close();
  }

  public void parseFileAndProcessLogLines() throws IOException, SQLException, ParseException {
    //System.out.println("Parsing the Log File");
    BufferedReader br = new BufferedReader(new FileReader(accesslog));

    List<List<String>> logData = new ArrayList<>();
    String line;
    while ((line = br.readLine()) != null) {
      String[] splittedLine = line.split("\\|"); // '\\|'
      logData.add(Arrays.asList(splittedLine));
    }

    //System.out.println("Inserting the parsed log file of " + logData.size() + " records into Database");
    insertLogDataIntoDB(logData);

    //System.out.println("Inserting over accessed ips into another table");
    Map<String, Integer> ipAddressCountMap = findIpAddressCounts(logData);
    insertExcessIpsIntoDB(ipAddressCountMap);
  }

  private Map<String, Integer> findIpAddressCounts(List<List<String>> logData) {
    Map<String, Integer> ipAddressCountMap = new HashMap<>();

    for (List<String> row : logData) {
      try {
        Date logDate = DATE_FORMAT.parse(row.get(0));
        String ipAddress = row.get(1);
        if (logDate.after(startDate) && logDate.before(endDate)) {
          //System.out.println("Found ip_address" + ip_address);
          if (ipAddressCountMap.containsKey(ipAddress)) {
            Integer count = ipAddressCountMap.get(ipAddress);
            ipAddressCountMap.put(ipAddress, count + 1);
          } else {
            ipAddressCountMap.put(ipAddress, 1);
          }
        }
      } catch (ParseException e) {
        System.out.println("Cannot parse the logDate, skipping the line");
      }
    }
    return ipAddressCountMap;
  }

  private void insertLogDataIntoDB(List<List<String>> logData) throws SQLException {
    String query = "INSERT INTO LOG_DATA (log_date, ip_address, request," +
        "status, user_agent) values (?,?,?,?,?) ";
    PreparedStatement preparedStatement = databaseConnection.prepareStatement(query);
    databaseConnection.setAutoCommit(false);

    for (List<String> row : logData) {
      try {
        Date logDate = DATE_FORMAT.parse(row.get(0));
        preparedStatement.setTimestamp(1, new Timestamp(logDate.getTime()));
        preparedStatement.setString(2, row.get(1));
        preparedStatement.setString(3, row.get(2));
        preparedStatement.setInt(4, Integer.parseInt(row.get(3)));
        preparedStatement.setString(5, row.get(4));
        preparedStatement.execute();
      } catch (ParseException e) {
        System.out.println("Cannot parse the logDate, skipping the line");
      } catch (SQLException e) {
        System.out.println("Cannot insert the log line, skipping the line");
      }
    }
    //System.out.println("Inserted "+ this.log_data.size() +" logs into log_Data");
    databaseConnection.commit();
  }

  public void insertExcessIpsIntoDB(Map<String, Integer> ipAddressCountMap) throws SQLException {
    String query = "INSERT INTO EXCESS_REQUESTS (ip_address, comments) values (?,?) ";
    PreparedStatement pstmt = databaseConnection.prepareStatement(String.valueOf(query));
    databaseConnection.setAutoCommit(false);
    System.out.println("Ips with excess requests:");

    for (String key : ipAddressCountMap.keySet()) {
      if (ipAddressCountMap.get(key) > threshold) {
        System.out.println("IP: " + key);
        try {
          pstmt.setString(1, key);
          pstmt.setString(2, "Threshold limit " + threshold + " reached");
          pstmt.execute();
        } catch (SQLException e) {
          System.out.println("Cannot insert the excess ip, skipping the line");
        }
      }
    }
    databaseConnection.commit();
  }

  private void parseStartDateAndComputeEndDate() {
    try {
      startDate = new SimpleDateFormat("yyyy-MM-dd.HH:mm:ss").parse(startDateString);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid start date");
    }

    Calendar calendar = Calendar.getInstance();
    calendar.setTime(startDate);
    if (duration.equalsIgnoreCase("daily")) {
      calendar.add(Calendar.DATE, 1);
    } else if (duration.equalsIgnoreCase("hourly")) {
      calendar.add(Calendar.HOUR, 1);
    } else {
      throw new IllegalArgumentException("Unknown duration: " + duration);
    }
    endDate = calendar.getTime();
  }

}