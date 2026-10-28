package benign;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SafeDao {
    public static String getUserById(Connection conn, int userId) throws SQLException {
        String query = "SELECT username FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getString(1);
            }
        }
        return null;
    }
}