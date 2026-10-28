package vulnerable;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class VulnSqlInjection {
    public void queryUser(Connection conn, String input) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM accounts WHERE id = '" + input + "'";
        ResultSet rs = stmt.executeQuery(query);
    }
}