<?php
/**
 * MonsterApps Web Portal - Enhanced App Store
 * Professional P2P app distribution with live node status and Mod support
 *
 * This file serves as the main web portal for the MonsterApps distributed app store.
 * It provides a user-friendly interface to browse, discover, and interact with
 * applications and nodes within the MonsterApps mesh network.
 *
 * Key features include:
 * - A dynamic App Store for discovering P2P distributed applications.
 * - A dedicated Mods section for client modifications.
 * - Real-time monitoring of connected network nodes.
 * - A live chat system for peer-to-peer communication.
 * - Robust security headers to protect against common web vulnerabilities.
 * - SEO-friendly structure for better discoverability.
 */

// Security headers for a secure web experience
header('X-Content-Type-Options: nosniff'); // Prevents MIME sniffing
header('X-Frame-Options: DENY');           // Prevents clickjacking
header('X-XSS-Protection: 1; mode=block'); // Enables XSS filtering

// Core Configuration for the MonsterApps Portal
$config = [
    'db_host' => 'localhost',           // Database host (e.g., 'localhost' or IP)
    'db_user' => 'root',                // Database username
    'db_password' => '',                // Database password (use strong passwords in production!)\
    'db_name' => 'monsterapps_mesh',    // Name of the MySQL database
    'node_timeout' => 300,              // Node heartbeat timeout in seconds (5 minutes)
    'chat_poll_interval' => 5000,       // Chat refresh interval in milliseconds (5 seconds)
    'max_chat_messages' => 100          // Maximum number of chat messages to display
];

/**
 * Establishes and returns a PDO database connection.
 * Uses a static variable to ensure only one connection is made per request lifecycle.
 * @param array $config The application configuration array containing database credentials.
 * @return PDO|null A PDO object on successful connection, or null on failure.
 */
function getDbConnection($config) {
    static $pdo = null; // Static variable to hold the PDO instance
    
    // Connect only if a connection doesn't already exist
    if ($pdo === null) {
        try {
            // Construct the DSN (Data Source Name) for MySQL
            $dsn = "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4";
            // Create a new PDO instance with error mode and default fetch mode
            $pdo = new PDO($dsn, $config['db_user'], $config['db_password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,         // Throw exceptions on errors
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC     // Fetch results as associative arrays
            ]);
        } catch (PDOException $e) {
            // Log database connection errors for debugging
            error_log("MonsterApps DB Connection Failed: " . $e->getMessage());
            return null; // Return null to indicate failure
        }
    }
    
    return $pdo; // Return the established PDO connection
}

// Start PHP session for user authentication and state management
session_start();

/**
 * Authenticates a network node based on provided HTTP headers.
 * This function is crucial for securing API endpoints and identifying clients.
 * @param array $headers Associative array of HTTP request headers.
 * @return bool True if authentication is successful, false otherwise.
 */
function authenticateNode($headers) {
    global $config; // Access the global configuration
    
    $pdo = getDbConnection($config); // Get database connection
    if (!$pdo) return false; // If DB connection fails, authentication fails
    
    // Extract necessary authentication parameters from headers
    $node_id = $headers['X-Node-ID'] ?? '';       // Unique ID of the client node
    $client_token = $headers['X-Client-Token'] ?? ''; // Secret token for client verification
    $username = $headers['X-Username'] ?? '';     // Username of the client node
    
    // Basic validation: Node ID and client token must not be empty
    if (empty($node_id) || empty(trim($client_token))) { // Trim client_token to handle whitespace issues
        error_log("Authentication failed: Missing node_id or client_token. Node ID: '$node_id', Client Token: '$client_token'");
        return false;
    }
    
    // Update node's last heartbeat and status in the database to mark it online
    // Use a prepared statement to prevent SQL injection
    $stmt = $pdo->prepare("
        UPDATE mesh_nodes 
        SET last_heartbeat = NOW(), status = 'online' 
        WHERE node_id = ? AND client_token = ?
    ");
    
    $result = $stmt->execute([$node_id, $client_token]); // Execute the update query
    
    // If update was successful and at least one row was affected, authenticate the session
    if ($result && $stmt->rowCount() > 0) {
        $_SESSION['node_id'] = $node_id;       // Store node ID in session
        $_SESSION['username'] = $username;     // Store username in session
        $_SESSION['authenticated'] = true;     // Mark session as authenticated
        return true;
    }
    
    error_log("Authentication failed: Invalid node_id or client_token. Node ID: '$node_id', Client Token: '$client_token'");
    return false; // Authentication failed
}

/**
 * Retrieves a list of currently online network nodes.
 * Nodes are considered online if their last heartbeat is within the configured timeout.
 * @param array $config The application configuration.
 * @return array An array of online node information.
 */
function getOnlineNodes($config) {
    $pdo = getDbConnection($config); // Get database connection
    if (!$pdo) return []; // Return empty array if DB connection fails
    
    $stmt = $pdo->prepare("
        SELECT node_id, username, ip_address, webserver_port, apps_count, 
               status, chat_enabled, last_heartbeat,
               TIMESTAMPDIFF(SECOND, last_heartbeat, NOW()) as seconds_ago
        FROM mesh_nodes 
        WHERE last_heartbeat > NOW() - INTERVAL ? SECOND
        AND status IN ('online', 'busy')
        ORDER BY last_heartbeat DESC
    ");
    
    $stmt->execute([$config['node_timeout']]); // Execute query with node timeout parameter
    return $stmt->fetchAll(); // Fetch all matching nodes
}

/**
 * Retrieves a list of available applications or mods from the network, with optional filtering.
 * This function powers the "App Store" and "Mods" tabs.
 * It also applies a rule: if an app's name contains "mod", it will be treated as a mod.
 * @param array $config The application configuration.
 * @param string|null $category_filter Optional category to filter items by.
 * @param string|null $search_term Optional search term to filter items by name.
 * @param bool|null $is_mod_filter Optional boolean to filter by is_mod (true for mods, false for apps, null for all).
 * @return array An array of available application/mod information.
 */
function getAvailableItems($config, $category_filter = null, $search_term = null, $is_mod_filter = null) {
    $pdo = getDbConnection($config); // Get database connection
    if (!$pdo) return []; // Return empty array if DB connection fails
    
    // Initialize WHERE conditions and parameters for the SQL query
    $where_conditions = [
        "mn.last_heartbeat > NOW() - INTERVAL {$config['node_timeout']} SECOND", // Node must be online
        "aa.status = 'available'" // Item must be marked as available
    ];
    $params = []; // Array to hold prepared statement parameters
    
    // Add category filter if provided
    if ($category_filter && $category_filter !== 'All') {
        $where_conditions[] = "aa.app_category = ?";
        $params[] = $category_filter;
    }
    
    // Add search term filter if provided
    if ($search_term) {
        $where_conditions[] = "aa.app_name LIKE ?";
        $params[] = "%{$search_term}%";
    }

    // Note: We don't apply is_mod_filter directly in the SQL query here.
    // Instead, we fetch all relevant items and then filter/modify `is_mod` flag in PHP
    // based on the "mod" keyword in the name, before applying the final filter.
    
    // Construct the full WHERE clause
    $where_clause = "WHERE " . implode(" AND ", $where_conditions);
    
    $stmt = $pdo->prepare("
        SELECT aa.*, mn.username, mn.status as node_status, mn.ip_address, mn.webserver_port,
               CASE WHEN mn.status = 'online' THEN 1 ELSE 0 END as available
        FROM app_availability aa
        JOIN mesh_nodes mn ON aa.node_id = mn.node_id
        {$where_clause}
        ORDER BY aa.app_name, mn.username
    ");
    
    $stmt->execute($params); // Execute the query with dynamic parameters
    $items = $stmt->fetchAll(); // Fetch all matching items

    // Post-processing: Apply "mod" keyword rule and final is_mod_filter
    $filtered_items = [];
    foreach ($items as $item) {
        // Rule: If app_name contains "mod" (case-insensitive), treat it as a mod.
        if (stripos($item['app_name'], 'mod') !== false) {
            $item['is_mod'] = true;
        } else {
            // Ensure it's explicitly false if not a mod by name and not already true from DB
            $item['is_mod'] = (bool)$item['is_mod']; 
        }

        // Apply the requested is_mod_filter
        if ($is_mod_filter === null || (bool)$item['is_mod'] === $is_mod_filter) {
            $filtered_items[] = $item;
        }
    }

    return $filtered_items; // Return the processed and filtered items
}

/**
 * Retrieves chat messages from the database.
 * Supports filtering by a minimum message ID and recipient node ID.
 * @param array $config The application configuration.
 * @param int $since_id The minimum message ID to retrieve (for fetching new messages).
 * @param string|null $node_id The recipient node ID (for direct messages) or null for broadcast.
 * @return array An array of chat messages.
 */
function getChatMessages($config, $since_id = 0, $node_id = null) {
    $pdo = getDbConnection($config); // Get database connection
    if (!$pdo) return []; // Return empty array if DB connection fails
    
    $where_conditions = ["cm.id > ?"]; // Always fetch messages newer than since_id
    $params = [$since_id]; // Add since_id to parameters
    
    // Add condition for direct or broadcast messages if a node_id is specified
    if ($node_id) {
        $where_conditions[] = "(cm.receiver_node_id = ? OR cm.message_type = 'broadcast')";
        $params[] = $node_id;
    }
    
    // Construct the full WHERE clause
    $where_clause = "WHERE " . implode(" AND ", $where_conditions);
    
    $stmt = $pdo->prepare("
        SELECT cm.id, cm.sender_node_id, mn.username, cm.message_type, 
               cm.content, cm.timestamp, cm.encrypted
        FROM chat_messages cm
        JOIN mesh_nodes mn ON cm.sender_node_id = mn.node_id
        {$where_clause}
        ORDER BY cm.timestamp DESC
        LIMIT {$config['max_chat_messages']}
    ");
    
    $stmt->execute($params); // Execute the query with dynamic parameters
    return array_reverse($stmt->fetchAll()); // Fetch and reverse to show newest at bottom
}

/**
 * Sends a chat message and stores it in the database.
 * Supports both broadcast and direct messages.
 * @param array $config The application configuration.
 * @param string $sender_node_id The ID of the sending node.
 * @param string $content The message content.
 * @param string $message_type 'broadcast' or 'direct'.
 * @param string|null $receiver_node_id The ID of the recipient node for direct messages.
 * @return bool True on success, false on failure.
 */
function sendChatMessage($config, $sender_node_id, $content, $message_type = 'broadcast', $receiver_node_id = null) {
    $pdo = getDbConnection($config); // Get database connection
    if (!$pdo) return false; // Return false if DB connection fails
    
    $stmt = $pdo->prepare("
        INSERT INTO chat_messages (sender_node_id, receiver_node_id, message_type, content)
        VALUES (?, ?, ?, ?)
    ");
    
    return $stmt->execute([$sender_node_id, $receiver_node_id, $message_type, $content]); // Execute insert
}

/**
 * Increments the download count for a specific app/mod.
 * @param array $config The application configuration.
 * @param string $app_token The unique token of the app/mod to increment.
 * @return bool True on success, false on failure.
 */
function incrementDownloadCount($config, $app_token) {
    $pdo = getDbConnection($config);
    if (!$pdo) return false;

    try {
        $stmt = $pdo->prepare("
            UPDATE app_availability
            SET downloads = downloads + 1
            WHERE app_token = ?
        ");
        return $stmt->execute([$app_token]);
    } catch (PDOException $e) {
        error_log("Error incrementing download count for token {$app_token}: " . $e->getMessage());
        return false;
    }
}


// Handle AJAX POST requests for dynamic content loading and interactions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json'); // Set response header to JSON
    
    $action = $_POST['action'] ?? ''; // Get the requested action from POST data
    
    switch ($action) {
        case 'get_nodes':
            $nodes = getOnlineNodes($config); // Fetch online nodes
            echo json_encode(['success' => true, 'nodes' => $nodes]);
            exit; // Terminate script after sending JSON response
            
        case 'get_apps':
            $category = $_POST['category'] ?? null; // Get category filter
            $search = $_POST['search'] ?? null;     // Get search term
            // Pass false to getAvailableItems to filter for non-mods (applications)
            $apps = getAvailableItems($config, $category, $search, false); 
            echo json_encode(['success' => true, 'apps' => $apps]);
            exit;

        case 'get_mods':
            $category = $_POST['category'] ?? null; // Get category filter
            $search = $_POST['search'] ?? null;     // Get search term
            // Pass true to getAvailableItems to filter for mods
            $mods = getAvailableItems($config, $category, $search, true); 
            echo json_encode(['success' => true, 'mods' => $mods]);
            exit;
            
        case 'get_chat':
            $since_id = intval($_POST['since_id'] ?? 0); // Get last chat ID for new messages
            $node_id = $_SESSION['node_id'] ?? null;     // Get current authenticated node ID
            $messages = getChatMessages($config, $since_id, $node_id); // Fetch chat messages
            echo json_encode(['success' => true, 'messages' => $messages]);
            exit;
            
        case 'send_chat':
            // Ensure user is authenticated before sending messages
            if (!isset($_SESSION['node_id'])) {
                echo json_encode(['success' => false, 'error' => 'Not authenticated to chat']);
                exit;
            }
            
            $content = trim($_POST['content'] ?? '');       // Get message content
            $message_type = $_POST['message_type'] ?? 'broadcast'; // Get message type
            $receiver_id = $_POST['receiver_id'] ?? null;   // Get receiver ID for direct messages
            
            // Validate message content
            if (empty($content)) {
                echo json_encode(['success' => false, 'error' => 'Message cannot be empty']);
                exit;
            }
            
            $success = sendChatMessage($config, $_SESSION['node_id'], $content, $message_type, $receiver_id);
            echo json_encode(['success' => $success]);
            exit;
            
        case 'verify_app':
            // This action allows the client to request verification of an app's hash from its host node.
            $app_token = $_POST['app_token'] ?? '';
            $download_url = $_POST['download_url'] ?? '';
            
            if ($app_token && $download_url) {
                // Construct the verification URL by replacing '/grab?' with '/verify?'
                $verify_url = str_replace('/grab?', '/verify?', $download_url) . "&token=" . $app_token;
                
                // Use cURL to make an HTTP request to the hosting node for verification
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $verify_url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return response as string
                curl_setopt($ch, CURLOPT_TIMEOUT, 10);          // Set a timeout for the request
                $response = curl_exec($ch);                     // Execute cURL request
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE); // Get HTTP status code
                curl_close($ch);                                // Close cURL session
                
                if ($http_code === 200) {
                    $verification = json_decode($response, true); // Decode JSON response
                    echo json_encode(['success' => true, 'verification' => $verification]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Verification failed or host unreachable']);
                }
            } else {
                echo json_encode(['success' => false, 'error' => 'Missing app_token or download_url for verification']);
            }
            exit;

        case 'increment_download':
            $app_token = $_POST['app_token'] ?? '';
            if (!empty($app_token)) {
                $success = incrementDownloadCount($config, $app_token);
                echo json_encode(['success' => $success]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Missing app_token for download increment']);
            }
            exit;
            
        default:
            echo json_encode(['success' => false, 'error' => 'Unknown action requested']);
            exit;
    }
}

// Check current authentication status for the HTML page rendering
$authenticated = false;
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated']) {
    $authenticated = true;
} else {
    // Attempt to authenticate from HTTP headers if not already authenticated via session
    $headers = getallheaders(); // Get all request headers
    if ($headers && authenticateNode($headers)) {
        $authenticated = true; // Mark as authenticated if successful
    }
}

// Handle invite links for seamless network joining
$invite_data = null;
if (isset($_GET['invite'])) {
    try {
        $invite_json = base64_decode($_GET['invite']); // Decode base64 invite data
        $invite_data = json_decode($invite_json, true); // Decode JSON invite data
    } catch (Exception $e) {
        // Log invalid invite link attempts
        error_log("Invalid invite link: " . $_GET['invite'] . " - " . $e->getMessage());
        // Optionally, redirect or show an error message to the user
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MonsterApps - Secure P2P App Store & Network | SecUpgrade Apps</title>
    <meta name="description" content="Discover and distribute secure, decentralized applications with MonsterApps, powered by SecUpgrade. Experience peer-to-peer app sharing, live network monitoring, and encrypted chat.">
    <meta name="keywords" content="MonsterApps, SecUpgrade, P2P app store, decentralized apps, secure software, mesh networking, peer-to-peer, app distribution, encrypted chat, open-source apps, community apps, network status, app marketplace">
    <meta name="author" content="SecUpgrade Technologies">
    <meta property="og:title" content="MonsterApps - Secure P2P App Store & Network">
    <meta property="og:description" content="Discover and distribute secure, decentralized applications with MonsterApps, powered by SecUpgrade. Experience peer-to-peer app sharing, live network monitoring, and encrypted chat.">
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://secupgrade.com/appstore.php"> <!-- Replace with your actual URL -->
    <link rel="canonical" href="https://secupgrade.com/appstore.php"> <!-- Replace with your actual URL -->
    
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🚀</text></svg>">
    
    <style>
        /* Global Reset and Box-Sizing */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        /* Body Styling: Font, Background, Min-Height */
        body {
            font-family: 'Inter', sans-serif; /* Modern, clean font */
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); /* Deep blue-grey gradient */
            color: #e2e8f0; /* Light off-white for text */
            min-height: 100vh; /* Full viewport height */
            display: flex; /* Use flexbox for overall layout */
            flex-direction: column; /* Stack header, main, footer vertically */
        }

        /* Header Styling: Sticky, Blurry Background */
        .header {
            background: rgba(30, 41, 59, 0.8); /* Semi-transparent dark background */
            backdrop-filter: blur(10px); /* Frosted glass effect */
            padding: 1rem 2rem; /* Vertical and horizontal padding */
            border-bottom: 1px solid #334155; /* Subtle bottom border */
            position: sticky; /* Make header sticky */
            top: 0; /* Stick to the top */
            z-index: 100; /* Ensure header is above other content */
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2); /* Soft shadow */
        }
        
        /* Header Content Layout */
        .header-content {
            max-width: 1200px; /* Max width for content alignment */
            margin: 0 auto; /* Center content */
            display: flex; /* Flexbox for logo and status */
            justify-content: space-between; /* Space between logo and status */
            align-items: center; /* Vertically align items */
        }
        
        /* Logo Styling */
        .logo {
            display: flex; /* Flexbox for icon and text */
            align-items: center; /* Vertically align */
            gap: 1rem; /* Space between icon and text */
            font-size: 1.5rem; /* Large font size */
            font-weight: bold; /* Bold text */
            color: #4ade80; /* Vibrant green color */
            text-shadow: 0 0 5px rgba(74, 222, 128, 0.5); /* Subtle glow */
        }
        
        /* Status Bar Styling */
        .status-bar {
            display: flex; /* Flexbox for indicators */
            align-items: center; /* Vertically align */
            gap: 1rem; /* Space between indicators */
            font-size: 0.9rem; /* Smaller font size */
        }
        
        /* Individual Status Indicator Styling */
        .status-indicator {
            display: flex; /* Flexbox for icon and text */
            align-items: center; /* Vertically align */
            gap: 0.5rem; /* Space between icon and text */
            padding: 0.25rem 0.75rem; /* Padding */
            border-radius: 1rem; /* Rounded corners */
            background: rgba(51, 65, 85, 0.5); /* Semi-transparent dark background */
            border: 1px solid #475569; /* Border for definition */
        }
        
        /* Online Status Specific Styling */
        .status-online { 
            background: rgba(34, 197, 94, 0.2); /* Light green background */
            color: #4ade80; /* Vibrant green text */
            border-color: #4ade80; /* Green border */
        }
        
        /* Offline Status Specific Styling */
        .status-offline { 
            background: rgba(239, 68, 68, 0.2); /* Light red background */
            color: #f87171; /* Red text */
            border-color: #f87171; /* Red border */
        }

        /* Main Content Container */
        .container {
            max-width: 1200px; /* Max width for content */
            margin: 0 auto; /* Center content */
            padding: 2rem; /* Overall padding */
            flex-grow: 1; /* Allow container to grow and take available space */
            display: flex;
            flex-direction: column;
        }

        /* Landing Page Section */
        .landing-page {
            background: rgba(30, 41, 59, 0.8);
            border-radius: 1.5rem;
            padding: 3rem;
            margin-bottom: 3rem;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
            border: 1px solid #334155;
            animation: fadeIn 1s ease-out;
        }

        .landing-page h1 {
            font-size: 3rem;
            color: #4ade80;
            margin-bottom: 1rem;
            text-shadow: 0 0 10px rgba(74, 222, 128, 0.7);
            line-height: 1.2;
        }

        .landing-page p {
            font-size: 1.2rem;
            color: #cbd5e1;
            margin-bottom: 2rem;
            line-height: 1.6;
            max-width: 800px;
            margin-left: auto;
            margin-right: auto;
        }

        .landing-page .cta-button {
            display: inline-block;
            background: linear-gradient(90deg, #4ade80, #22c55e);
            color: #0f172a;
            padding: 1rem 2.5rem;
            border-radius: 0.75rem;
            font-size: 1.2rem;
            font-weight: bold;
            text-decoration: none;
            transition: all 0.3s ease;
            box-shadow: 0 5px 15px rgba(74, 222, 128, 0.4);
        }

        .landing-page .cta-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(74, 222, 128, 0.6);
            background: linear-gradient(90deg, #22c55e, #4ade80);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .feature-item {
            background: rgba(15, 23, 42, 0.6);
            border-radius: 1rem;
            padding: 2rem;
            text-align: left;
            border: 1px solid #334155;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .feature-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.5);
        }

        .feature-item h3 {
            font-size: 1.5rem;
            color: #4ade80;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .feature-item p {
            font-size: 1rem;
            color: #a0aec0;
            line-height: 1.5;
        }

        /* Tab Navigation Styling */
        .tabs {
            display: flex; /* Flexbox for tabs */
            gap: 1rem; /* Space between tabs */
            margin-bottom: 2rem; /* Margin below tabs */
            border-bottom: 1px solid #334155; /* Separator line */
            overflow-x: auto; /* Allow horizontal scrolling on small screens */
            white-space: nowrap; /* Prevent tabs from wrapping */
            padding-bottom: 5px; /* Space for the active border */
        }
        
        /* Individual Tab Button Styling */
        .tab {
            padding: 1rem 1.5rem; /* Padding inside tabs */
            background: none; /* No background */
            border: none; /* No default border */
            color: #94a3b8; /* Grey text color */
            cursor: pointer; /* Pointer cursor on hover */
            border-bottom: 2px solid transparent; /* Transparent bottom border for active indicator */
            transition: all 0.3s ease; /* Smooth transitions */
            font-size: 1rem; /* Standard font size */
            font-weight: 600; /* Semi-bold */
            border-radius: 0.5rem 0.5rem 0 0; /* Rounded top corners */
        }
        
        /* Tab Hover State */
        .tab:hover {
            color: #e2e8f0; /* Lighter text on hover */
            background: rgba(51, 65, 85, 0.3); /* Subtle background on hover */
        }
        
        /* Active Tab State */
        .tab.active {
            color: #4ade80; /* Vibrant green for active tab */
            border-bottom-color: #4ade80; /* Green bottom border for active indicator */
            background: rgba(30, 41, 59, 0.5); /* Slightly darker background for active tab */
        }
        
        /* Tab Content Styling */
        .tab-content {
            display: none; /* Hide by default */
            background: rgba(30, 41, 59, 0.8); /* Semi-transparent dark background */
            border-radius: 1rem; /* Rounded corners */
            padding: 2rem; /* Padding inside tab content */
            border: 1px solid #334155; /* Border */
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3); /* Soft shadow */
            min-height: 400px; /* Minimum height for content */
        }
        
        /* Active Tab Content Display */
        .tab-content.active {
            display: block; /* Show active tab content */
        }
        
        /* Filter Bar Styling */
        .filters {
            display: flex; /* Flexbox for filter elements */
            gap: 1rem; /* Space between filters */
            margin-bottom: 2rem; /* Margin below filters */
            flex-wrap: wrap; /* Allow filters to wrap on smaller screens */
        }
        
        /* Search Box Styling */
        .search-box {
            flex: 1; /* Allow search box to grow */
            min-width: 250px; /* Minimum width */
            padding: 0.75rem; /* Padding */
            border: 1px solid #475569; /* Border color */
            border-radius: 0.5rem; /* Rounded corners */
            background: rgba(30, 41, 59, 0.5); /* Semi-transparent background */
            color: #e2e8f0; /* Text color */
            font-size: 1rem; /* Font size */
            transition: border-color 0.3s ease; /* Smooth border transition */
        }
        
        /* Search Box Focus State */
        .search-box:focus {
            outline: none; /* Remove default outline */
            border-color: #4ade80; /* Green border on focus */
            box-shadow: 0 0 0 3px rgba(74, 222, 128, 0.3); /* Subtle glow on focus */
        }
        
        /* Filter Select Dropdown Styling */
        .filter-select {
            padding: 0.75rem; /* Padding */
            border: 1px solid #475569; /* Border color */
            border-radius: 0.5rem; /* Rounded corners */
            background: rgba(30, 41, 59, 0.5); /* Semi-transparent background */
            color: #e2e8f0; /* Text color */
            cursor: pointer; /* Pointer cursor */
            appearance: none; /* Remove default select arrow */
            -webkit-appearance: none; /* For Webkit browsers */
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='%23e2e8f0'%3E%3Cpath fill-rule='evenodd' d='M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z' clip-rule='evenodd'/%3E%3C/svg%3E"); /* Custom SVG arrow */
            background-repeat: no-repeat;
            background-position: right 0.75rem center;
            background-size: 1.25rem;
        }

        /* Grid Layout for App Cards */
        .grid {
            display: grid; /* Grid layout */
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); /* Responsive columns */
            gap: 1.5rem; /* Gap between grid items */
        }
        
        /* Card Base Styling */
        .card {
            background: rgba(30, 41, 59, 0.8); /* Semi-transparent dark background */
            border: 1px solid #334155; /* Border */
            border-radius: 1rem; /* Rounded corners */
            padding: 1.5rem; /* Padding */
            transition: all 0.3s ease; /* Smooth transitions for hover effects */
            backdrop-filter: blur(10px); /* Frosted glass effect */
            display: flex; /* Flexbox for internal layout */
            flex-direction: column; /* Stack content vertically */
            justify-content: space-between; /* Distribute space */
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2); /* Soft shadow */
        }
        
        /* Card Hover State */
        .card:hover {
            transform: translateY(-5px); /* Lift effect on hover */
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4); /* Larger shadow on hover */
            border-color: #4ade80; /* Green border on hover */
        }
        
        /* App Card Specific Styling */
        .app-card {
            position: relative; /* For absolute positioning of badges if needed */
        }
        
        /* App Card Header Layout */
        .app-header {
            display: flex; /* Flexbox for title/meta and badge */
            justify-content: space-between; /* Space between elements */
            align-items: flex-start; /* Align to top */
            margin-bottom: 1rem; /* Margin below header */
        }
        
        /* App Title Styling */
        .app-title {
            font-size: 1.25rem; /* Larger font size */
            font-weight: bold; /* Bold text */
            color: #e2e8f0; /* Light text color */
            margin-bottom: 0.25rem; /* Small margin below title */
        }
        
        /* App Meta Information Styling */
        .app-meta {
            color: #94a3b8; /* Grey text color */
            font-size: 0.875rem; /* Smaller font size */
        }
        
        /* Availability Badge Styling */
        .availability-badge {
            padding: 0.25rem 0.75rem; /* Padding */
            border-radius: 1rem; /* Highly rounded corners */
            font-size: 0.75rem; /* Small font size */
            font-weight: bold; /* Bold text */
            text-transform: uppercase; /* Uppercase text */
            white-space: nowrap; /* Prevent wrapping */
        }
        
        /* Available Status Badge */
        .available {
            background: rgba(34, 197, 94, 0.2); /* Light green background */
            color: #4ade80; /* Vibrant green text */
        }
        
        /* Offline Status Badge */
        .offline {
            background: rgba(239, 68, 68, 0.2); /* Light red background */
            color: #f87171; /* Red text */
        }

        /* Mod Specific Styling */
        .mod-card .app-header .app-title, .mod-card .app-meta {
            color: #FFD700; /* Gold color for mod titles */
        }
        .mod-card .availability-badge.available {
            background: rgba(255, 215, 0, 0.2); /* Light gold background */
            color: #FFD700; /* Gold text */
        }
        .mod-card .download-btn.available {
            background: #FFD700; /* Gold background */
            color: #0f172a; /* Dark text */
            box-shadow: 0 3px 10px rgba(255, 215, 0, 0.3); /* Gold shadow */
        }
        .mod-card .download-btn.available:hover {
            background: #e6c200; /* Darker gold on hover */
            box-shadow: 0 5px 15px rgba(255, 215, 0, 0.5); /* Larger gold shadow */
        }

        /* App Statistics Styling */
        .app-stats {
            display: flex; /* Flexbox for stats items */
            flex-wrap: wrap; /* Allow stats to wrap */
            gap: 1rem; /* Space between stats items */
            margin: 1rem 0; /* Vertical margin */
            font-size: 0.875rem; /* Smaller font size */
            color: #94a3b8; /* Grey text color */
        }
        
        /* Download Button Styling */
        .download-btn {
            width: 100%; /* Full width */
            padding: 0.75rem; /* Padding */
            border: none; /* No border */
            border-radius: 0.5rem; /* Rounded corners */
            font-weight: bold; /* Bold text */
            cursor: pointer; /* Pointer cursor */
            transition: all 0.3s ease; /* Smooth transitions */
            font-size: 1rem; /* Standard font size */
            margin-top: auto; /* Push to bottom of card */
        }
        
        /* Available Download Button */
        .download-btn.available {
            background: #4ade80; /* Vibrant green background */
            color: #0f172a; /* Dark text color */
            box-shadow: 0 3px 10px rgba(74, 222, 128, 0.3); /* Green shadow */
        }
        
        /* Available Download Button Hover State */
        .download-btn.available:hover {
            background: #22c55e; /* Darker green on hover */
            transform: translateY(-2px); /* Lift effect */
            box-shadow: 0 5px 15px rgba(74, 222, 128, 0.5); /* Larger green shadow */
        }
        
        /* Offline Download Button */
        .download-btn.offline {
            background: #374151; /* Dark grey background */
            color: #6b7280; /* Lighter grey text */
            cursor: not-allowed; /* Not-allowed cursor */
            box-shadow: none; /* No shadow */
        }
        
        /* Chat Container Styling */
        .chat-container {
            height: 500px; /* Fixed height */
            display: flex; /* Flexbox layout */
            flex-direction: column; /* Stack messages and input vertically */
            background: rgba(15, 23, 42, 0.5); /* Semi-transparent dark background */
            border-radius: 1rem; /* Rounded corners */
            overflow: hidden; /* Hide overflowing content */
            border: 1px solid #334155; /* Border */
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3); /* Soft shadow */
        }
        
        /* Chat Messages Area */
        .chat-messages {
            flex: 1; /* Allow messages area to grow */
            padding: 1rem; /* Padding */
            overflow-y: auto; /* Enable vertical scrolling */
            border-bottom: 1px solid #334155; /* Separator from input */
            display: flex; /* Use flex to stack messages */
            flex-direction: column; /* Stack messages vertically */
            gap: 0.75rem; /* Space between messages */
        }
        
        /* Individual Chat Message Styling */
        .chat-message {
            padding: 0.75rem; /* Padding */
            border-radius: 0.5rem; /* Rounded corners */
            background: rgba(30, 41, 59, 0.5); /* Semi-transparent dark background */
            border: 1px solid #475569; /* Subtle border */
        }
        
        /* Message Header Layout */
        .message-header {
            display: flex; /* Flexbox for sender and time */
            justify-content: space-between; /* Space between sender and time */
            margin-bottom: 0.5rem; /* Margin below header */
            font-size: 0.875rem; /* Smaller font size */
        }
        
        /* Message Sender Styling */
        .message-sender {
            font-weight: bold; /* Bold sender name */
            color: #4ade80; /* Vibrant green for sender */
        }
        
        /* Message Time Styling */
        .message-time {
            color: #94a3b8; /* Grey text for time */
        }
        
        /* Message Content Styling */
        .message-content {
            color: #e2e8f0; /* Light text for content */
            word-wrap: break-word; /* Break long words */
        }
        
        /* Chat Input Area Layout */
        .chat-input {
            display: flex; /* Flexbox for input and button */
            padding: 1rem; /* Padding */
            gap: 1rem; /* Space between input and button */
            align-items: center; /* Vertically align items */
        }
        
        /* Chat Textarea Styling */
        .chat-text {
            flex: 1; /* Allow textarea to grow */
            padding: 0.75rem; /* Padding */
            border: 1px solid #475569; /* Border */
            border-radius: 0.5rem; /* Rounded corners */
            background: rgba(30, 41, 59, 0.5); /* Semi-transparent background */
            color: #e2e8f0; /* Text color */
            resize: vertical; /* Allow vertical resizing */
            min-height: 40px; /* Minimum height */
            max-height: 120px; /* Maximum height */
            font-family: 'Inter', sans-serif; /* Consistent font */
        }
        
        /* Send Button Styling */
        .send-btn {
            padding: 0.75rem 1.5rem; /* Padding */
            background: #4ade80; /* Vibrant green background */
            color: #0f172a; /* Dark text color */
            border: none; /* No border */
            border-radius: 0.5rem; /* Rounded corners */
            font-weight: bold; /* Bold text */
            cursor: pointer; /* Pointer cursor */
            transition: all 0.3s ease; /* Smooth transitions */
            box-shadow: 0 3px 10px rgba(74, 222, 128, 0.3); /* Green shadow */
        }
        
        /* Send Button Hover State */
        .send-btn:hover {
            background: #22c55e; /* Darker green on hover */
            transform: translateY(-2px); /* Lift effect */
            box-shadow: 0 5px 15px rgba(74, 222, 128, 0.5); /* Larger green shadow */
        }
        
        /* Node List Styling */
        .node-list {
            display: flex; /* Flexbox for nodes */
            flex-direction: column; /* Stack nodes vertically */
            gap: 1rem; /* Space between nodes */
        }
        
        /* Node Card Styling (reusing .card) */
        .node-card {
            display: flex; /* Flexbox for info and stats */
            justify-content: space-between; /* Space between elements */
            align-items: center; /* Vertically align */
            /* Inherits .card styles */
        }
        
        /* Node Info Styling */
        .node-info {
            flex: 1; /* Allow info to grow */
        }
        
        /* Node Name Styling */
        .node-name {
            font-weight: bold; /* Bold text */
            color: #e2e8f0; /* Light text color */
            font-size: 1.1rem;
        }
        
        /* Node ID Styling */
        .node-id {
            color: #94a3b8; /* Grey text */
            font-size: 0.875rem; /* Smaller font size */
            font-family: monospace; /* Monospaced font for IDs */
        }
        
        /* Node Stats Styling */
        .node-stats {
            display: flex; /* Flexbox for stats items */
            flex-wrap: wrap; /* Allow stats to wrap */
            gap: 1rem; /* Space between stats items */
            align-items: center; /* Vertically align */
            color: #94a3b8; /* Grey text */
            font-size: 0.875rem; /* Smaller font size */
        }
        
        /* Loading Message Styling */
        .loading {
            text-align: center; /* Center text */
            padding: 2rem; /* Padding */
            color: #94a3b8; /* Grey text */
            font-style: italic;
        }
        
        /* Error Message Styling */
        .error {
            background: rgba(239, 68, 68, 0.1); /* Light red background */
            border: 1px solid #ef4444; /* Red border */
            color: #fca5a5; /* Light red text */
            padding: 1rem; /* Padding */
            border-radius: 0.5rem; /* Rounded corners */
            margin-bottom: 1rem; /* Margin below error */
            font-weight: bold;
        }

        /* Category Warning Styling */
        .category-warning {
            color: #f87171; /* Red text for warning */
            font-size: 0.85rem;
            margin-top: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(239, 68, 68, 0.1);
            padding: 0.5rem 0.75rem;
            border-radius: 0.5rem;
            border: 1px solid #ef4444;
        }
        .category-warning svg {
            min-width: 16px; /* Ensure icon doesn't shrink */
            min-height: 16px;
        }
        
        /* Invite Banner Styling */
        .invite-banner {
            background: linear-gradient(135deg, #4ade80, #22c55e); /* Green gradient */
            color: #0f172a; /* Dark text color */
            padding: 1.5rem; /* Padding */
            border-radius: 1rem; /* Rounded corners */
            margin-bottom: 2rem; /* Margin below banner */
            text-align: center; /* Center text */
            box-shadow: 0 5px 20px rgba(74, 222, 128, 0.4); /* Green shadow */
            animation: slideInFromTop 0.8s ease-out;
        }
        
        /* Invite Banner Title */
        .invite-title {
            font-size: 1.5rem; /* Larger font size */
            font-weight: bold; /* Bold text */
            margin-bottom: 0.75rem; /* Margin below title */
        }

        /* Footer Styling */
        .footer {
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(10px);
            padding: 1.5rem 2rem;
            border-top: 1px solid #334155;
            text-align: center;
            font-size: 0.9rem;
            color: #94a3b8;
            margin-top: 2rem;
        }

        .footer a {
            color: #4ade80;
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer a:hover {
            color: #22c55e;
            text-decoration: underline;
        }
        
        /* Animations */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideInFromTop {
            from { transform: translateY(-100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        /* Responsive Adjustments */
        @media (max-width: 768px) {
            .container {
                padding: 1rem; /* Smaller padding on mobile */
            }
            
            .header-content {
                flex-direction: column; /* Stack header items vertically */
                gap: 1rem; /* Space between stacked items */
            }
            
            .tabs {
                padding-bottom: 0; /* Adjust padding for smaller screens */
            }

            .tab {
                padding: 0.75rem 1rem; /* Smaller tab padding */
                font-size: 0.9rem; /* Smaller tab font size */
            }
            
            .filters {
                flex-direction: column; /* Stack filters vertically */
            }
            
            .grid {
                grid-template-columns: 1fr; /* Single column layout for cards */
            }

            .landing-page {
                padding: 2rem;
            }

            .landing-page h1 {
                font-size: 2rem;
            }

            .landing-page p {
                font-size: 1rem;
            }

            .landing-page .cta-button {
                padding: 0.8rem 2rem;
                font-size: 1rem;
            }

            .features-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo">
                🚀 MonsterApps Store
            </div>
            <div class="status-bar">
                <div class="status-indicator" id="connection-status">
                    <span class="pulse">⏳</span>
                    <span>Connecting...</span>
                </div>
                <div class="status-indicator" id="nodes-status">
                    <span>🌐</span>
                    <span id="nodes-count">0 Nodes</span>
                </div>
                <?php if ($authenticated): // Display authenticated user's status ?>
                <div class="status-indicator status-online">
                    <span>✅</span>
                    <span><?= htmlspecialchars($_SESSION['username']) ?></span>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </header>

    <main class="container">
        <?php if ($invite_data): // Display invitation banner if an invite link is present ?>
        <div class="invite-banner">
            <div class="invite-title">🎉 Network Invitation</div>
            <p>You've been invited to join <strong><?= htmlspecialchars($invite_data['username']) ?></strong>'s MonsterApps network! Connect your client to start sharing and discovering.</p>
            <p class="app-meta">Node ID: <code><?= htmlspecialchars($invite_data['node_id'] ?? 'N/A') ?></code></p>
        </div>
        <?php endif; ?>

        <!-- Landing Page Area -->
        <section class="landing-page" id="landing-page">
            <h1>Unlock Decentralized Software with <span style="color: #4ade80;">MonsterApps</span> by SecUpgrade</h1>
            <p><strong>MonsterApps</strong>, a pioneering initiative by SecUpgrade, revolutionizes software distribution through a robust <strong>peer-to-peer (P2P) mesh network</strong>. Discover, share, and manage applications securely and efficiently, bypassing traditional centralized app stores. Experience true digital freedom with our advanced PFS encryption and live node connectivity.</p>
            <a href="#app-tabs" class="cta-button" onclick="showAppTabs()">Explore Apps Now</a>

            <div class="features-grid">
                <div class="feature-item">
                    <h3><span style="color: #4ade80;">🔗</span> Decentralized P2P Network</h3>
                    <p>Leverage a powerful mesh network for direct peer-to-peer app distribution. No central points of failure, ensuring resilient and censorship-resistant software access. Ideal for secure and private app sharing.</p>
                </div>
                <div class="feature-item">
                    <h3><span style="color: #4ade80;">🔒</span> Advanced PFS Encryption</h3>
                    <p>All communications and app transfers are secured with Perfect Forward Secrecy (PFS) encryption. Your data remains private and protected, even if long-term keys are compromised. Trust in SecUpgrade's commitment to security.</p>
                </div>
                <div class="feature-item">
                    <h3><span style="color: #4ade80;">⚡</span> Real-time Node Discovery</h3>
                    <p>Our intelligent MySQL-based node discovery system ensures you're always connected to the most active and relevant peers. Find new applications and expand your network effortlessly, enhancing your P2P experience.</p>
                </p>
                <div class="feature-item">
                    <h3><span style="color: #4ade80;">💬</span> Integrated Live Chat</h3>
                    <p>Communicate directly with other network participants through our secure, real-time chat. Collaborate, share insights, and build a vibrant community around decentralized software. Connect with fellow SecUpgrade users.</p>
                </div>
            </div>
        </section>

        <!-- Main Application Tabs - Initially hidden -->
        <div id="app-tabs" style="display: none;">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('store')">🛒 App Store</button>
                <button class="tab" onclick="switchTab('mods')">🔧 Mods</button>
                <button class="tab" onclick="switchTab('nodes')">🌐 Network Nodes</button>
                <button class="tab" onclick="switchTab('chat')">💬 Live Chat</button>
                <button class="tab" onclick="switchTab('debug')">⚙️ Debug Tools</button>
            </div>

            <!-- App Store Tab Content -->
            <div class="tab-content active" id="store-tab">
                <h2 style="color: #4ade80; margin-bottom: 1.5rem;">Browse Decentralized Applications</h2>
                <p style="color: #a0aec0; margin-bottom: 1.5rem;">Discover and download a wide range of secure, peer-to-peer applications shared by the MonsterApps community.</p>
                <div class="filters">
                    <input type="text" class="search-box" id="search-apps" placeholder="🔍 Search apps by name or node..." onkeyup="filterApps()" aria-label="Search apps">
                    <select class="filter-select" id="category-filter-apps" onchange="filterApps()" aria-label="Filter apps by category">
                        <option value="All">All Categories</option>
                        <option value="Games">Games</option>
                        <option value="Utilities">Utilities</option>
                        <option value="Development">Development</option>
                        <option value="Graphics">Graphics</option>
                        <option value="Network">Network</option>
                        <option value="Business">Business</option>
                        <option value="Security">Security Tools</option>
                    </select>
                </div>
                <div class="grid" id="apps-grid" role="list">
                    <div class="loading">Loading decentralized apps from the MonsterApps network...</div>
                </div>
            </div>

            <!-- Mods Tab Content -->
            <div class="tab-content" id="mods-tab">
                <h2 style="color: #FFD700; margin-bottom: 1.5rem;">Community-Created Mods</h2>
                <p style="color: #a0aec0; margin-bottom: 1.5rem;">Enhance your MonsterApps client with powerful, community-developed modifications. Mods can extend functionality and customize your experience.</p>
                <div class="filters">
                    <input type="text" class="search-box" id="search-mods" placeholder="🔍 Search mods by name or node..." onkeyup="filterMods()" aria-label="Search mods">
                    <select class="filter-select" id="category-filter-mods" onchange="filterMods()" aria-label="Filter mods by category">
                        <option value="All">All Categories</option>
                        <option value="Mod">Mod</option>
                        <option value="Client Tool">Client Tool</option>
                        <option value="Plugin">Plugin</option>
                        <option value="Utility">Utility</option>
                    </select>
                </div>
                <div class="grid" id="mods-grid" role="list">
                    <div class="loading">Loading community mods from the MonsterApps network...</div>
                </div>
            </div>

            <!-- Network Nodes Tab Content -->
            <div class="tab-content" id="nodes-tab">
                <h2 style="color: #4ade80; margin-bottom: 1.5rem;">Active MonsterApps Network Nodes</h2>
                <p style="color: #a0aec0; margin-bottom: 1.5rem;">Monitor the live status of connected peers in the MonsterApps mesh network. Each node contributes to the decentralized app distribution. Find out who's online and sharing!</p>
                <div class="node-list" id="nodes-list" role="list">
                    <div class="loading">Discovering active network nodes...</div>
                </div>
            </div>

            <!-- Chat Tab Content -->
            <div class="tab-content" id="chat-tab">
                <h2 style="color: #4ade80; margin-bottom: 1.5rem;">MonsterApps Live P2P Chat</h2>
                <p style="color: #a0aec0; margin-bottom: 1.5rem;">Engage in secure, real-time conversations with other MonsterApps users across the network. Discuss apps, share tips, and connect with the community.</p>
                <div class="chat-container">
                    <div class="chat-messages" id="chat-messages" role="log" aria-live="polite">
                        <div class="loading">Loading live chat messages...</div>
                    </div>
                    <?php if ($authenticated): // Only show chat input if authenticated ?>
                    <div class="chat-input">
                        <textarea class="chat-text" id="chat-input" placeholder="Type your secure message here..." rows="2" aria-label="Chat message input"></textarea>
                        <button class="send-btn" onclick="sendMessage()">Send Secure Message</button>
                    </div>
                    <?php else: ?>
                    <div style="padding: 1rem; text-align: center; color: #94a3b8;">
                        Connect your MonsterApps client to participate in the decentralized chat. <br>
                        <a href="https://github.com/JJustis/monsterapps" style="color: #4ade80; text-decoration: underline;">Download the client now!</a>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Debug Tools Tab -->
            <div class="tab-content" id="debug-tab">
                <h2 style="color: #4ade80; margin-bottom: 1.5rem;">🔧 MonsterApps Debug & Diagnostics</h2>
                <p style="color: #a0aec0; margin-bottom: 1.5rem;">
                    Advanced tools for network administrators and developers to diagnose app verification, node connectivity, and other mesh network issues. Use with caution.
                </p>
                
                <div style="display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap;">
                    <button onclick="refreshAllHashes()" class="cta-button" style="background: #4ade80; color: #0f172a; box-shadow: none;">
                        🔄 Refresh All App Hashes
                    </button>
                    <button onclick="showDebugInfo()" class="cta-button" style="background: #2196F3; color: white; box-shadow: none;">
                        📊 Show Node Debug Info
                    </button>
                    <button onclick="testConnections()" class="cta-button" style="background: #FF9800; color: white; box-shadow: none;">
                        🌐 Test Node Connections
                    </button>
                </div>
                
                <div id="debug-output" style="background: rgba(15, 23, 42, 0.5); border-radius: 0.5rem; padding: 1rem; font-family: monospace; white-space: pre-wrap; min-height: 300px; max-height: 500px; overflow-y: auto; border: 1px solid #334155; color: #e2e8f0;">
                    Click a debug tool button above to see real-time results and network diagnostics here.
                </div>
            </div>
        </div> <!-- End of app-tabs -->
    </main>

    <footer class="footer">
        <p>&copy; <?= date('Y') ?> MonsterApps by <a href="https://secupgrade.com" target="_blank" rel="noopener noreferrer">SecUpgrade Technologies</a>. All rights reserved. | <a href="https://secupgrade.com/privacy" target="_blank" rel="noopener noreferrer">Privacy Policy</a></p>
        <p>Building the future of decentralized app distribution. Join our secure P2P network today.</p>
    </footer>

    <script>
        let lastChatId = 0;
        let currentTab = 'store'; // Default tab
        let allItems = []; // Stores all fetched items (apps and mods)
        let nodes = []; // Stores fetched node data
        
        // Function to show the app tabs and hide the landing page
        function showAppTabs() {
            document.getElementById('landing-page').style.display = 'none';
            document.getElementById('app-tabs').style.display = 'block';
            // Ensure the store tab is active and loaded when transitioning from landing page
            switchTab('store');
        }

        // Debug functions (kept as is, for advanced users)
        function refreshAllHashes() {
            const output = document.getElementById('debug-output');
            output.textContent = 'Refreshing app hashes on connected nodes...\n';
            
            nodes.forEach(node => {
                if (node.status === 'online') {
                    const refreshUrl = `http://${node.ip_address}:${node.webserver_port || 9001}/refresh_hashes`;
                    
                    fetch(refreshUrl)
                        .then(response => response.json())
                        .then(data => {
                            output.textContent += `\n--- ${node.username} (${node.node_id.substring(0, 8)}...) ---\n`;
                            output.textContent += `  Status: ${data.success ? 'Success' : 'Failed'}\n`;
                            output.textContent += `  Updated: ${data.updated_count} apps\n`;
                            output.textContent += `  Total: ${data.total_items} apps\n`;
                            if (data.errors && data.errors.length > 0) {
                                output.textContent += `  Errors: ${data.errors.join(', ')}\n`;
                            }
                        })
                        .catch(error => {
                            output.textContent += `\n--- ${node.username} (${node.node_id.substring(0, 8)}...) ---\n`;
                            output.textContent += `  Error during refresh: ${error.message}\n`;
                        });
                }
            });
        }
        
        function showDebugInfo() {
            const output = document.getElementById('debug-output');
            output.textContent = 'Gathering detailed debug information from nodes...\n';
            
            nodes.forEach(node => {
                if (node.status === 'online') {
                    const debugUrl = `http://${node.ip_address}:${node.webserver_port || 9001}/debug`;
                    
                    fetch(debugUrl)
                        .then(response => response.json())
                        .then(data => {
                            output.textContent += `\n=== DEBUG INFO: ${node.username} (${node.node_id.substring(0, 8)}...) ===\n`;
                            output.textContent += `Server Status: ${data.server_status}\n`;
                            output.textContent += `Total Apps (hosted): ${data.total_apps}\n`;
                            output.textContent += `Total Mods (hosted): ${data.total_mods}\n`;
                            output.textContent += `Web Server Port: ${data.web_server_port}\n\n`;
                            
                            if (data.apps && data.apps.length > 0) {
                                output.textContent += `Hosted Apps Details:\n`;
                                data.apps.forEach(app => {
                                    output.textContent += `  - Name: ${app.name} (Mod: ${app.is_mod ? 'Yes' : 'No'})\n`;
                                    output.textContent += `    Token: ${app.app_token}\n`;
                                    output.textContent += `    File Exists: ${app.file_exists ? 'Yes' : 'No'}\n`;
                                    output.textContent += `    Size Match: ${app.size_match ? 'Yes' : 'No'}\n`;
                                    output.textContent += `    Stored Size: ${app.stored_size} bytes\n`;
                                    output.textContent += `    Current Size: ${app.current_size} bytes\n`;
                                    output.textContent += `    Hash: ${app.stored_hash}\n\n`;
                                });
                            } else {
                                output.textContent += `No apps hosted on this node.\n\n`;
                            }
                        })
                        .catch(error => {
                            output.textContent += `\n=== DEBUG INFO ERROR: ${node.username} (${node.node_id.substring(0, 8)}...) ===\n`;
                            output.textContent += `  Could not fetch debug info: ${error.message}\n`;
                        });
                }
            });
        }
        
        function testConnections() {
            const output = document.getElementById('debug-output');
            output.textContent = 'Initiating connection tests to all online nodes...\n';
            
            if (nodes.length === 0) {
                output.textContent += 'No online nodes to test. Please ensure clients are running and connected.\n';
                return;
            }

            nodes.forEach(node => {
                const testUrl = `http://${node.ip_address}:${node.webserver_port || 9001}/status`;
                const startTime = Date.now();
                
                fetch(testUrl)
                    .then(response => {
                        const responseTime = Date.now() - startTime;
                        if (response.ok) {
                            return response.json().then(data => {
                                output.textContent += `\n✅ ${node.username} (${node.node_id.substring(0, 8)}...): Online (${responseTime}ms)\n`;
                                output.textContent += `  Apps Available: ${data.apps_available || 0}\n`;
                                output.textContent += `  Node ID (reported): ${data.node_id || 'N/A'}\n`;
                            });
                        } else {
                            output.textContent += `\n❌ ${node.username} (${node.node_id.substring(0, 8)}...): HTTP Error ${response.status} (${responseTime}ms)\n`;
                            return Promise.reject(`HTTP Error: ${response.status}`);
                        }
                    })
                    .catch(error => {
                        const responseTime = Date.now() - startTime;
                        output.textContent += `\n❌ ${node.username} (${node.node_id.substring(0, 8)}...): Connection Failed (${responseTime}ms) - ${error.message}\n`;
                    });
            });
        }

        // Tab switching logic
        function switchTab(tabName) {
            // Update tab buttons' active state
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
            
            // Update tab content visibility
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(`${tabName}-tab`).classList.add('active');
            
            currentTab = tabName; // Update global current tab state
            
            // Load content specific to the activated tab
            if (tabName === 'store') {
                loadApps();
            } else if (tabName === 'mods') {
                loadMods();
            } else if (tabName === 'nodes') {
                loadNodes();
            } else if (tabName === 'chat') {
                loadChat();
            } else if (tabName === 'debug') {
                // Debug tab content is static until a button is clicked
                document.getElementById('debug-output').textContent = 'Debug tools ready. Click a button above to start diagnostics.';
            }
        }
        
        // Load apps from the PHP backend via AJAX
        function loadApps() {
            const grid = document.getElementById('apps-grid');
            grid.innerHTML = '<div class="loading">Loading decentralized applications from the MonsterApps network...</div>'; // Show loading
            
            fetch('', { // Fetch from the same PHP file
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_apps' // Request 'get_apps' action
            })
            .then(response => response.json()) // Parse JSON response
            .then(data => {
                if (data.success) {
                    displayItems(data.apps, 'apps-grid', false); // Display them, explicitly not a mod section
                } else {
                    showError('Failed to load apps from the network. ' + (data.error || 'Please try again.'));
                }
            })
            .catch(error => {
                console.error('Error loading apps:', error);
                showError('Network error loading apps. Please check your connection.');
            });
        }

        // Load mods from the PHP backend via AJAX
        function loadMods() {
            const grid = document.getElementById('mods-grid');
            grid.innerHTML = '<div class="loading">Loading community mods from the MonsterApps network...</div>'; // Show loading
            
            fetch('', { // Fetch from the same PHP file
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_mods' // Request 'get_mods' action
            })
            .then(response => response.json()) // Parse JSON response
            .then(data => {
                if (data.success) {
                    displayItems(data.mods, 'mods-grid', true); // Display them, explicitly a mod section
                } else {
                    showError('Failed to load mods from the network. ' + (data.error || 'Please try again.'));
                }
            })
            .catch(error => {
                console.error('Error loading mods:', error);
                showError('Network error loading mods. Please check your connection.');
            });
        }
        
        // Display apps or mods in the grid format
        function displayItems(itemsToShow, gridId, isModSection) {
            const grid = document.getElementById(gridId);
            
            if (itemsToShow.length === 0) {
                grid.innerHTML = `<div class="loading">No ${isModSection ? 'mods' : 'applications'} currently available in this section. Share your own or connect to more nodes!</div>`;
                return;
            }
            
            grid.innerHTML = itemsToShow.map(item => {
                let warningMessage = '';
                // Check for category mismatch and generate warning
                if (isModSection && !item.is_mod) {
                    warningMessage = `
                        <div class="category-warning">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>
                            </svg>
                            <span>This app might be miscategorized.</span>
                        </div>
                    `;
                } else if (!isModSection && item.is_mod) {
                    warningMessage = `
                        <div class="category-warning">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>
                            </svg>
                            <span>This mod might be miscategorized.</span>
                        </div>
                    `;
                }

                return `
                <div class="card app-card ${item.is_mod ? 'mod-card' : ''}" role="listitem" aria-label="${item.is_mod ? 'Mod' : 'App'}: ${escapeHtml(item.app_name)} by ${escapeHtml(item.username)}">
                    <div class="app-header">
                        <div>
                            <div class="app-title">${escapeHtml(item.app_name)}</div>
                            <div class="app-meta">by ${escapeHtml(item.username)} • ${escapeHtml(item.app_category)}</div>
                        </div>
                        <div class="availability-badge ${item.available ? 'available' : 'offline'}">
                            ${item.available ? '🟢 Online' : '🔴 Offline'}
                        </div>
                    </div>
                    ${warningMessage}
                    <div class="app-stats">
                        <span>💾 ${formatFileSize(item.file_size)}</span>
                        <span>⬇️ Downloads: ${item.downloads || 0}</span>
                        <span>🕒 Last Verified: ${formatTimestamp(item.last_verified)}</span>
                    </div>
                    <button class="download-btn ${item.available ? 'available' : 'offline'}" 
                            onclick="downloadApp('${escapeHtml(item.app_token)}', '${escapeHtml(item.download_url)}', '${escapeHtml(item.app_name)}')"
                            ${!item.available ? 'disabled' : ''}
                            aria-label="${item.available ? 'Download ' + escapeHtml(item.app_name) : 'Node Offline for ' + escapeHtml(item.app_name)}">
                        ${item.available ? '⬇️ Download ' + (item.is_mod ? 'Mod' : 'App') : '⏳ Node Offline'}
                    </button>
                </div>
                `;
            }).join('');
        }
        
        // Filter apps based on search term and category
        function filterApps() {
            const searchTerm = document.getElementById('search-apps').value.toLowerCase();
            const category = document.getElementById('category-filter-apps').value;
            
            fetch('', { // Fetch from the same PHP file
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=get_apps&search=${encodeURIComponent(searchTerm)}&category=${encodeURIComponent(category)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayItems(data.apps, 'apps-grid', false); // Explicitly not a mod section
                } else {
                    showError('Failed to filter apps. ' + (data.error || 'Please try again.'));
                }
            })
            .catch(error => {
                console.error('Error filtering apps:', error);
                showError('Network error filtering apps.');
            });
        }

        // Filter mods based on search term and category
        function filterMods() {
            const searchTerm = document.getElementById('search-mods').value.toLowerCase();
            const category = document.getElementById('category-filter-mods').value;
            
            fetch('', { // Fetch from the same PHP file
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=get_mods&search=${encodeURIComponent(searchTerm)}&category=${encodeURIComponent(category)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayItems(data.mods, 'mods-grid', true); // Explicitly a mod section
                } else {
                    showError('Failed to filter mods. ' + (data.error || 'Please try again.'));
                }
            })
            .catch(error => {
                console.error('Error filtering mods:', error);
                showError('Network error filtering mods.');
            });
        }
        
        // Initiate app download after verification
        function downloadApp(appToken, downloadUrl, appName) {
            const btn = event.target; // Get the button element that was clicked
            const originalText = btn.textContent;
            btn.textContent = '🔄 Verifying...'; // Show verification status
            btn.disabled = true; // Disable button during process
            
            // First, verify the app's integrity with the hosting node
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=verify_app&app_token=${appToken}&download_url=${encodeURIComponent(downloadUrl)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.verification) {
                    const verification = data.verification;
                    
                    if (verification.verified) {
                        // If verification passes, proceed with download
                        btn.textContent = '⬇️ Downloading...';
                        window.open(downloadUrl, '_blank'); // Open download URL in new tab
                        showNotification(`Downloading ${appName} securely...`, 'success');
                        
                        // Increment download count via AJAX after initiating download
                        fetch('', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: `action=increment_download&app_token=${appToken}`
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (!data.success) {
                                console.error('Failed to increment download count:', data.error);
                            }
                        })
                        .catch(error => {
                            console.error('Network error incrementing download count:', error);
                        });

                        // Reset button after a short delay
                        setTimeout(() => {
                            btn.textContent = originalText;
                            btn.disabled = false;
                            if (currentTab === 'store') {
                                loadApps(); // Refresh app list to update download counts
                            } else if (currentTab === 'mods') {
                                loadMods(); // Refresh mod list to update download counts
                            }
                        }, 3000);
                    } else {
                        // If verification fails, show detailed error
                        console.error('App verification failed:', verification);
                        
                        let errorMsg = `App integrity check failed for "${appName}".\n\n`;
                        errorMsg += `Expected Hash: ${verification.stored_hash}\n`;
                        errorMsg += `Received Hash: ${verification.current_hash}\n`;
                        errorMsg += `File Size: ${formatFileSize(verification.file_size)}\n`;
                        errorMsg += `\nThis indicates the file may be corrupted or tampered with. Do NOT proceed with installation.`;
                        
                        showNotification('App verification failed! Possible corruption.', 'error');
                        alert(errorMsg); // Use alert for critical errors as a fallback
                        
                        btn.textContent = originalText;
                        btn.disabled = false;
                    }
                } else {
                    console.error('Verification request failed:', data);
                    showNotification(`Verification failed: ${data.error || 'Unknown error'}`, 'error');
                    btn.textContent = originalText;
                    btn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Network error during verification:', error);
                showNotification('Network error during app verification.', 'error');
                btn.textContent = originalText;
                btn.disabled = false;
            });
        }
        
        // Load network nodes via AJAX
        function loadNodes() {
            const list = document.getElementById('nodes-list');
            list.innerHTML = '<div class="loading">Discovering active MonsterApps network nodes...</div>'; // Show loading
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_nodes'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    nodes = data.nodes; // Store fetched nodes globally
                    displayNodes(nodes); // Display them
                    updateNodesCount(nodes.length); // Update node count in header
                } else {
                    showError('Failed to load network nodes. ' + (data.error || 'Please try again.'));
                }
            })
            .catch(error => {
                console.error('Error loading nodes:', error);
                showError('Network error loading nodes. Your client might be offline.');
            });
        }
        
        // Display network nodes
        function displayNodes(nodesToShow) {
            const list = document.getElementById('nodes-list');
            
            if (nodesToShow.length === 0) {
                list.innerHTML = '<div class="loading">No MonsterApps nodes currently online. Ensure your client is running and connected!</div>';
                return;
            }
            
            list.innerHTML = nodesToShow.map(node => `
                <div class="card node-card" role="listitem" aria-label="Node: ${escapeHtml(node.username)}">
                    <div class="node-info">
                        <div class="node-name">${escapeHtml(node.username)}</div>
                        <div class="node-id">ID: ${node.node_id.substring(0, 16)}...</div>
                    </div>
                    <div class="node-stats">
                        <span class="status-indicator ${node.status === 'online' ? 'status-online' : 'status-offline'}">
                            ${node.status === 'online' ? '🟢' : '🔴'} ${node.status.toUpperCase()}
                        </span>
                        <span>📱 ${node.apps_count} apps shared</span>
                        <span>💬 ${node.chat_enabled ? 'Chat Enabled' : 'No Chat'}</span>
                        <span>🕒 Last Seen: ${node.seconds_ago}s ago</span>
                    </div>
                </div>
            `).join('');
        }
        
        // Load chat messages via AJAX
        function loadChat() {
            const chatContainer = document.getElementById('chat-messages');
            if (lastChatId === 0 && chatContainer.children.length === 0) {
                 chatContainer.innerHTML = '<div class="loading">Loading live chat messages...</div>'; // Initial loading message
            }
           
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=get_chat&since_id=${lastChatId}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Remove initial loading message if present
                    if (lastChatId === 0 && chatContainer.querySelector('.loading')) {
                        chatContainer.innerHTML = '';
                    }
                    displayChatMessages(data.messages);
                    if (data.messages.length > 0) {
                        lastChatId = Math.max(...data.messages.map(m => m.id)); // Update lastChatId
                    }
                } else {
                    console.error('Failed to load chat messages:', data.error);
                    // Optionally show a non-intrusive error in chat area
                }
            })
            .catch(error => {
                console.error('Network error loading chat:', error);
                // Optionally show a network error in chat area
            });
        }
        
        // Display chat messages
        function displayChatMessages(messages) {
            const chatContainer = document.getElementById('chat-messages');
            
            if (messages.length === 0 && lastChatId === 0) {
                chatContainer.innerHTML = '<div class="loading">No messages yet. Be the first to start a secure conversation!</div>';
                return;
            }
            
            messages.forEach(message => {
                const messageEl = document.createElement('div');
                messageEl.className = 'chat-message';
                messageEl.innerHTML = `
                    <div class="message-header">
                        <span class="message-sender">${escapeHtml(message.username)}</span>
                        <span class="message-time">${formatTimestamp(message.timestamp)}</span>
                    </div>
                    <div class="message-content">${escapeHtml(message.content)}</div>
                `;
                chatContainer.appendChild(messageEl);
            });
            
            // Scroll to bottom to show newest messages
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
        
        // Send chat message via AJAX
        function sendMessage() {
            const input = document.getElementById('chat-input');
            const content = input.value.trim();
            
            if (!content) return; // Don't send empty messages
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=send_chat&content=${encodeURIComponent(content)}&message_type=broadcast` // Currently only supports broadcast
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    input.value = ''; // Clear input field
                    loadChat(); // Refresh chat to see sent message and new ones
                } else {
                    showNotification('Failed to send message. ' + (data.error || 'Please try again.'), 'error');
                }
            })
            .catch(error => {
                console.error('Error sending message:', error);
                showNotification('Network error sending message. Check your client connection.', 'error');
            });
        }
        
        // Utility function to escape HTML for security (prevent XSS)
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Utility function to format file sizes for readability
        function formatFileSize(bytes) {
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            if (bytes === 0) return '0 B';
            const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
            return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        // Utility function to format timestamps for display
        function formatTimestamp(timestamp) {
            // Assuming timestamp is in a format Date constructor can parse
            const date = new Date(timestamp);
            if (isNaN(date.getTime())) { // Check for invalid date
                return "Invalid Date";
            }
            // Format as HH:MM:SS
            return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        
        // Update the count of online nodes in the header
        function updateNodesCount(count) {
            document.getElementById('nodes-count').textContent = `${count} Nodes`;
        }
        
        // Update the overall connection status indicator in the header
        function updateConnectionStatus(online) {
            const status = document.getElementById('connection-status');
            if (online) {
                status.innerHTML = '<span>✅</span><span>Connected</span>';
                status.className = 'status-indicator status-online';
            } else {
                status.innerHTML = '<span>❌</span><span>Offline</span>';
                status.className = 'status-indicator status-offline';
            }
        }
        
        // Display a temporary error message at the top of the container
        function showError(message) {
            const container = document.querySelector('.container');
            const error = document.createElement('div');
            error.className = 'error';
            error.textContent = message;
            // Insert before the tabs or landing page
            container.insertBefore(error, container.firstChild.nextSibling); 
            
            setTimeout(() => error.remove(), 7000); // Remove after 7 seconds
        }
        
        // Display a temporary notification (success/error) at the top right
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 1rem;
                border-radius: 0.75rem; /* More rounded */
                color: white;
                z-index: 1000;
                font-weight: bold;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                background: ${type === 'success' ? '#22c55e' : '#ef4444'};
                animation: fadeIn 0.5s ease-out;
            `;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => notification.remove(), 4000); // Remove after 4 seconds
        }
        
        // Auto-refresh mechanism for tabs
        function startAutoRefresh() {
            setInterval(() => {
                if (currentTab === 'store') {
                    loadApps();
                } else if (currentTab === 'mods') {
                    loadMods();
                } else if (currentTab === 'nodes') {
                    loadNodes();
                } else if (currentTab === 'chat') {
                    loadChat();
                }
            }, <?= $config['chat_poll_interval'] ?>); // Use configured interval
        }
        
        // Initial setup when the DOM is fully loaded
        document.addEventListener('DOMContentLoaded', function() {
            const chatInput = document.getElementById('chat-input');
            if (chatInput) {
                // Add keypress listener for sending chat messages with Enter
                chatInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) { // Send on Enter, allow Shift+Enter for new line
                        e.preventDefault(); // Prevent default Enter behavior (new line)
                        sendMessage();
                    }
                });
            }
            
            // Initial load of content for the default tab (store)
            // This will be called after the landing page is potentially shown/hidden
            // We don't call switchTab('store') here directly, as the landing page handles the initial display.
            
            // Start the auto-refresh for dynamic content
            startAutoRefresh();

            // Check if there's an invite link in the URL, if so, hide landing page and show tabs
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.has('invite')) {
                showAppTabs();
            }
        });
    </script>
</body>
</html>
