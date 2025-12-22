package com.yourapp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

public class JavaBackendServer {

    public static void main(String[] args) throws IOException {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        ApiHandler handler = new ApiHandler();

        // Base API contexts
        server.createContext("/api/auth/login", handler);
        server.createContext("/api/auth/signup", handler);
        server.createContext("/api/user", handler);
        server.createContext("/api/subscriptions", handler);
        server.createContext("/api/bills", handler);
        server.createContext("/api/expenses", handler);
        server.createContext("/api/pantry", handler);

        // Add test endpoint
        server.createContext("/api/test", exchange -> {
            setCorsHeaders(exchange);
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "Backend is working!");
            response.put("timestamp", System.currentTimeMillis());
            sendResponse(exchange, 200, response.toString());
        });

        server.setExecutor(Executors.newFixedThreadPool(10));

        System.out.println("✅ Server started on port " + port);
        System.out.println("📡 Available endpoints:");
        System.out.println("   POST /api/auth/login");
        System.out.println("   POST /api/auth/signup");
        System.out.println("   GET  /api/test (to check if server is working)");
        server.start();
    }

    private static void setCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String responseBody) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");

        if (statusCode == 204 || responseBody == null || responseBody.isEmpty()) {
            exchange.sendResponseHeaders(statusCode, -1);
        } else {
            byte[] responseBytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }

    static class ApiHandler implements HttpHandler {

        private long getAuthenticatedUserId(HttpExchange exchange) {
            return 1L; // Hardcoded for your development
        }

        // Helper to get ID from URL query string (?id=123)
        private Map<String, String> queryToMap(String query) {
            Map<String, String> result = new HashMap<>();
            if (query == null) return result;
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                if (entry.length > 1) {
                    result.put(entry[0], entry[1]);
                }
            }
            return result;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCorsHeaders(exchange);

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            System.out.println("📨 Request: " + method + " " + path);

            try (Connection conn = DatabaseUtil.getConnection()) {
                long userId = getAuthenticatedUserId(exchange);

                if(path.equals("/api/auth/login")) {
                    if ("POST".equals(method)) handleLogin(exchange, conn);
                    else sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
                } else if (path.equals("/api/auth/signup")) {
                    if ("POST".equals(method)) handleSignup(exchange, conn);
                    else sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
                } else if (path.equals("/api/user")) {
                    if ("GET".equals(method)) handleGetUser(exchange, conn, userId);
                    else if ("PUT".equals(method)) handleUpdateIncome(exchange, conn, userId);
                } else if (path.equals("/api/subscriptions")) {
                    if ("GET".equals(method)) handleGetSubscriptions(exchange, conn, userId);
                    else if ("POST".equals(method)) handlePostSubscription(exchange, conn, userId);
                    else if ("PUT".equals(method)) handleUpdateSubscription(exchange, conn, userId);
                    else if ("DELETE".equals(method)) handleDeleteSubscriptionBody(exchange, conn, userId);
                } else if (path.equals("/api/bills")) {
                    if ("GET".equals(method)) handleGetBills(exchange, conn, userId);
                    else if ("POST".equals(method)) handlePostBill(exchange, conn, userId);
                    else if ("PUT".equals(method)) handleUpdateBillStatus(exchange, conn, userId);
                    else if ("DELETE".equals(method)) handleDeleteBillBody(exchange, conn, userId);
                } else if (path.equals("/api/expenses")) {
                    if ("GET".equals(method)) handleGetExpenses(exchange, conn, userId);
                    else if ("POST".equals(method)) handlePostExpense(exchange, conn, userId);
                    else if ("DELETE".equals(method)) handleDeleteExpenseBody(exchange, conn, userId);
                } else if (path.equals("/api/pantry")) {
                    if ("GET".equals(method)) handleGetPantryItems(exchange, conn, userId);
                    else if ("POST".equals(method)) handlePostPantryItem(exchange, conn, userId);
                    else if ("DELETE".equals(method)) handleDeletePantryItemBody(exchange, conn, userId);
                } else {
                    sendResponse(exchange, 404, "{\"error\": \"Endpoint not found\"}");
                }
            } catch (SQLException e) {
                handleError(exchange, "Database error", e);
            } catch (Exception e) {
                handleError(exchange, "Server error", e);
            }
        }

        private void handleError(HttpExchange exchange, String type, Exception e) throws IOException {
            System.err.println("❌ " + type + ": " + e.getMessage());
            e.printStackTrace();
            JSONObject error = new JSONObject();
            error.put("status", "error");
            error.put("message", type + ": " + e.getMessage());
            sendResponse(exchange, 500, error.toString());
        }

        // ----------------------------------------------------
        // RE-WRITTEN DELETE METHODS (The Fix)
        // ----------------------------------------------------

        private void handleDeleteBillBody(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            long idToDelete = -1;
            try {
                // Try getting ID from URL first (?id=5)
                Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
                if (params.containsKey("id")) {
                    idToDelete = Long.parseLong(params.get("id"));
                } else {
                    // Try getting ID from JSON body
                    String requestBody = readRequestBody(exchange);
                    if (!requestBody.isEmpty()) {
                        JSONObject json = new JSONObject(requestBody);
                        idToDelete = json.getLong("id");
                    }
                }

                if (idToDelete == -1) {
                    sendResponse(exchange, 400, "{\"error\": \"Missing ID for deletion\"}");
                    return;
                }

                System.out.println("🗑️ Attempting to delete BILL ID: " + idToDelete + " for User: " + userId);
                String sql = "DELETE FROM bills WHERE id=? AND user_id=?";
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setLong(1, idToDelete);
                    ps.setLong(2, userId);
                    int rows = ps.executeUpdate(); // Use executeUpdate for DELETE

                    if (rows > 0) {
                        System.out.println("✅ Successfully deleted Bill ID: " + idToDelete);
                        sendResponse(exchange, 200, "{\"status\":\"success\",\"message\":\"Bill deleted\"}");
                    } else {
                        System.out.println("⚠️ No bill found with ID: " + idToDelete);
                        sendResponse(exchange, 404, "{\"error\":\"Bill not found\"}");
                    }
                }
            } catch (Exception e) {
                handleError(exchange, "Delete failed", e);
            }
        }

        // Apply same logic to Expenses, Subscriptions, and Pantry
        private void handleDeleteExpenseBody(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            long idToDelete = -1;
            Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
            if (params.containsKey("id")) idToDelete = Long.parseLong(params.get("id"));
            else {
                String body = readRequestBody(exchange);
                if (!body.isEmpty()) idToDelete = new JSONObject(body).getLong("id");
            }

            String sql = "DELETE FROM expenses WHERE id=? AND user_id=?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, idToDelete);
                ps.setLong(2, userId);
                if (ps.executeUpdate() > 0) sendResponse(exchange, 200, "{\"status\":\"success\"}");
                else sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
            }
        }

        private void handleDeleteSubscriptionBody(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            long idToDelete = -1;
            Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
            if (params.containsKey("id")) idToDelete = Long.parseLong(params.get("id"));
            else {
                String body = readRequestBody(exchange);
                if (!body.isEmpty()) idToDelete = new JSONObject(body).getLong("id");
            }

            String sql = "DELETE FROM subscriptions WHERE id=? AND user_id=?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, idToDelete);
                ps.setLong(2, userId);
                if (ps.executeUpdate() > 0) sendResponse(exchange, 200, "{\"status\":\"success\"}");
                else sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
            }
        }

        private void handleDeletePantryItemBody(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            long idToDelete = -1;
            Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
            if (params.containsKey("id")) idToDelete = Long.parseLong(params.get("id"));
            else {
                String body = readRequestBody(exchange);
                if (!body.isEmpty()) idToDelete = new JSONObject(body).getLong("id");
            }

            String sql = "DELETE FROM pantry_items WHERE id=? AND user_id=?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, idToDelete);
                ps.setLong(2, userId);
                if (ps.executeUpdate() > 0) sendResponse(exchange, 200, "{\"status\":\"success\"}");
                else sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
            }
        }

        // ----------------------------------------------------
        // AUTH, GET, POST (Remaining original code)
        // ----------------------------------------------------

        private void handleLogin(HttpExchange exchange, Connection conn) throws IOException, SQLException {
            try {
                String requestBody = readRequestBody(exchange);
                JSONObject json = new JSONObject(requestBody);
                String email = json.getString("email");
                String password = json.getString("password");

                String sql = "SELECT * FROM users WHERE email = ?";
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, email);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next() && rs.getString("password").equals(password)) {
                            JSONObject resp = new JSONObject();
                            resp.put("status", "success");
                            resp.put("name", rs.getString("name"));
                            sendResponse(exchange, 200, resp.toString());
                        } else {
                            sendResponse(exchange, 401, "{\"error\":\"Invalid credentials\"}");
                        }
                    }
                }
            } catch (Exception e) { handleError(exchange, "Login error", e); }
        }

        private void handleSignup(HttpExchange exchange, Connection conn) throws IOException, SQLException {
            try {
                String requestBody = readRequestBody(exchange);
                JSONObject json = new JSONObject(requestBody);
                String insertSql = "INSERT INTO users (name, email, password, monthly_income) VALUES (?, ?, ?, 0.00)";
                try (PreparedStatement ps = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    ps.setString(1, json.getString("name"));
                    ps.setString(2, json.getString("email"));
                    ps.setString(3, json.getString("password"));
                    ps.executeUpdate();
                    sendResponse(exchange, 201, "{\"status\":\"success\"}");
                }
            } catch (Exception e) { handleError(exchange, "Signup error", e); }
        }

        private void handleGetUser(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            String sql = "SELECT * FROM users WHERE id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        JSONObject user = new JSONObject();
                        user.put("name", rs.getString("name"));
                        user.put("income", rs.getBigDecimal("monthly_income"));
                        sendResponse(exchange, 200, user.toString());
                    }
                }
            }
        }

        private void handleUpdateIncome(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            String body = readRequestBody(exchange);
            JSONObject json = new JSONObject(body);
            String sql = "UPDATE users SET monthly_income = ? WHERE id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setBigDecimal(1, json.getBigDecimal("income"));
                ps.setLong(2, userId);
                ps.executeUpdate();
                sendResponse(exchange, 200, "{\"status\":\"success\"}");
            }
        }

        private void handleGetSubscriptions(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONArray array = new JSONArray();
            String sql = "SELECT * FROM subscriptions WHERE user_id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject item = new JSONObject();
                        item.put("id", rs.getLong("id"));
                        item.put("name", rs.getString("name"));
                        item.put("price", rs.getBigDecimal("price"));
                        array.put(item);
                    }
                }
            }
            sendResponse(exchange, 200, array.toString());
        }

        private void handlePostSubscription(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONObject json = new JSONObject(readRequestBody(exchange));
            String sql = "INSERT INTO subscriptions (name, price, currency, billing_cycle, next_due_date, category, payment_method, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, json.getString("name"));
                ps.setBigDecimal(2, json.getBigDecimal("price"));
                ps.setString(3, "₹");
                ps.setString(4, "monthly");
                ps.setDate(5, Date.valueOf(json.getString("nextDue")));
                ps.setString(6, "Other");
                ps.setString(7, "Other");
                ps.setLong(8, userId);
                ps.executeUpdate();
                sendResponse(exchange, 201, "{\"status\":\"success\"}");
            }
        }

        private void handleUpdateSubscription(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONObject json = new JSONObject(readRequestBody(exchange));
            String sql = "UPDATE subscriptions SET name=?, price=? WHERE id=? AND user_id=?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, json.getString("name"));
                ps.setBigDecimal(2, json.getBigDecimal("price"));
                ps.setLong(3, json.getLong("id"));
                ps.setLong(4, userId);
                ps.executeUpdate();
                sendResponse(exchange, 200, "{\"status\":\"success\"}");
            }
        }

        private void handleGetBills(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONArray array = new JSONArray();
            String sql = "SELECT * FROM bills WHERE user_id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject item = new JSONObject();
                        item.put("id", rs.getLong("id"));
                        item.put("name", rs.getString("name"));
                        item.put("amount", rs.getBigDecimal("amount"));
                        item.put("dueDate", rs.getDate("due_date").toString());
                        item.put("status", rs.getString("status"));
                        array.put(item);
                    }
                }
            }
            sendResponse(exchange, 200, array.toString());
        }

        private void handlePostBill(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONObject json = new JSONObject(readRequestBody(exchange));
            String sql = "INSERT INTO bills (name, amount, due_date, status, user_id) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, json.getString("name"));
                ps.setBigDecimal(2, json.getBigDecimal("amount"));
                ps.setDate(3, Date.valueOf(json.getString("dueDate")));
                ps.setString(4, "Unpaid");
                ps.setLong(5, userId);
                ps.executeUpdate();
                sendResponse(exchange, 201, "{\"status\":\"success\"}");
            }
        }

        private void handleUpdateBillStatus(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONObject json = new JSONObject(readRequestBody(exchange));
            String sql = "UPDATE bills SET status='Paid' WHERE id=? AND user_id=?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, json.getLong("id"));
                ps.setLong(2, userId);
                ps.executeUpdate();
                sendResponse(exchange, 200, "{\"status\":\"success\"}");
            }
        }

        private void handleGetExpenses(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONArray array = new JSONArray();
            String sql = "SELECT * FROM expenses WHERE user_id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject item = new JSONObject();
                        item.put("id", rs.getLong("id"));
                        item.put("name", rs.getString("name"));
                        item.put("amount", rs.getBigDecimal("amount"));
                        array.put(item);
                    }
                }
            }
            sendResponse(exchange, 200, array.toString());
        }

        private void handlePostExpense(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONObject json = new JSONObject(readRequestBody(exchange));
            String sql = "INSERT INTO expenses (name, amount, date, category, user_id) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, json.getString("name"));
                ps.setBigDecimal(2, json.getBigDecimal("amount"));
                ps.setDate(3, new Date(System.currentTimeMillis()));
                ps.setString(4, "General");
                ps.setLong(5, userId);
                ps.executeUpdate();
                sendResponse(exchange, 201, "{\"status\":\"success\"}");
            }
        }

        private void handleGetPantryItems(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONArray array = new JSONArray();
            String sql = "SELECT * FROM pantry_items WHERE user_id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JSONObject item = new JSONObject();
                        item.put("id", rs.getLong("id"));
                        item.put("name", rs.getString("name"));
                        array.put(item);
                    }
                }
            }
            sendResponse(exchange, 200, array.toString());
        }

        private void handlePostPantryItem(HttpExchange exchange, Connection conn, long userId) throws IOException, SQLException {
            JSONObject json = new JSONObject(readRequestBody(exchange));
            String sql = "INSERT INTO pantry_items (name, location, quantity, expiry_date, user_id) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, json.getString("name"));
                ps.setString(2, "Kitchen");
                ps.setString(3, "1");
                ps.setDate(4, new Date(System.currentTimeMillis() + 864000000L));
                ps.setLong(5, userId);
                ps.executeUpdate();
                sendResponse(exchange, 201, "{\"status\":\"success\"}");
            }
        }

        private String readRequestBody(HttpExchange exchange) throws IOException {
            try (InputStream is = exchange.getRequestBody()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
    }

    static class DatabaseUtil {
        private static final String DB_URL = "jdbc:mysql://localhost:3306/home_app_db";
        private static final String USER   = "root";
        private static final String PASS   = "Maruthi@2345";

        static {
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
                System.out.println("✅ Driver Loaded");
            } catch (Exception e) { e.printStackTrace(); }
        }

        public static Connection getConnection() throws SQLException {
            return DriverManager.getConnection(DB_URL, USER, PASS);
        }
    }
}