<?php
/**
 * MonsterApps Web Portal - Enhanced App Store
 * Professional P2P app distribution with live node status
 */

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Configuration
$config = [
    'db_host' => 'localhost',
    'db_user' => 'root',
    'db_password' => '',
    'db_name' => 'monsterapps_mesh',
    'node_timeout' => 300, // 5 minutes
    'chat_poll_interval' => 5000, // 5 seconds in milliseconds
    'max_chat_messages' => 100
];

// Database connection
function getDbConnection($config) {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $dsn = "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4";
            $pdo = new PDO($dsn, $config['db_user'], $config['db_password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            return null;
        }
    }
    
    return $pdo;
}

// Authentication and session management
session_start();

function authenticateNode($headers) {
    global $config;
    
    $pdo = getDbConnection($config);
    if (!$pdo) return false;
    
    $node_id = $headers['X-Node-ID'] ?? '';
    $client_token = $headers['X-Client-Token'] ?? '';
    $username = $headers['X-Username'] ?? '';
    
    if (empty($node_id) || empty($client_token)) {
        return false;
    }
    
    // Verify node exists and update last seen
    $stmt = $pdo->prepare("
        UPDATE mesh_nodes 
        SET last_heartbeat = NOW(), status = 'online' 
        WHERE node_id = ? AND client_token = ?
    ");
    
    $result = $stmt->execute([$node_id, $client_token]);
    
    if ($result && $stmt->rowCount() > 0) {
        $_SESSION['node_id'] = $node_id;
        $_SESSION['username'] = $username;
        $_SESSION['authenticated'] = true;
        return true;
    }
    
    return false;
}

function getOnlineNodes($config) {
    $pdo = getDbConnection($config);
    if (!$pdo) return [];
    
    $stmt = $pdo->prepare("
        SELECT node_id, username, ip_address, webserver_port, apps_count, 
               status, chat_enabled, last_heartbeat,
               TIMESTAMPDIFF(SECOND, last_heartbeat, NOW()) as seconds_ago
        FROM mesh_nodes 
        WHERE last_heartbeat > NOW() - INTERVAL ? SECOND
        AND status IN ('online', 'busy')
        ORDER BY last_heartbeat DESC
    ");
    
    $stmt->execute([$config['node_timeout']]);
    return $stmt->fetchAll();
}

function getAvailableApps($config, $category_filter = null, $search_term = null) {
    $pdo = getDbConnection($config);
    if (!$pdo) return [];
    
    $where_conditions = [
        "mn.last_heartbeat > NOW() - INTERVAL {$config['node_timeout']} SECOND",
        "aa.status = 'available'"
    ];
    $params = [];
    
    if ($category_filter && $category_filter !== 'All') {
        $where_conditions[] = "aa.app_category = ?";
        $params[] = $category_filter;
    }
    
    if ($search_term) {
        $where_conditions[] = "aa.app_name LIKE ?";
        $params[] = "%{$search_term}%";
    }
    
    $where_clause = "WHERE " . implode(" AND ", $where_conditions);
    
    $stmt = $pdo->prepare("
        SELECT aa.*, mn.username, mn.status as node_status, mn.ip_address, mn.webserver_port,
               CASE WHEN mn.status = 'online' THEN 1 ELSE 0 END as available
        FROM app_availability aa
        JOIN mesh_nodes mn ON aa.node_id = mn.node_id
        {$where_clause}
        ORDER BY aa.app_name, mn.username
    ");
    
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function getChatMessages($config, $since_id = 0, $node_id = null) {
    $pdo = getDbConnection($config);
    if (!$pdo) return [];
    
    $where_conditions = ["cm.id > ?"];
    $params = [$since_id];
    
    if ($node_id) {
        $where_conditions[] = "(cm.receiver_node_id = ? OR cm.message_type = 'broadcast')";
        $params[] = $node_id;
    }
    
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
    
    $stmt->execute($params);
    return array_reverse($stmt->fetchAll());
}

function sendChatMessage($config, $sender_node_id, $content, $message_type = 'broadcast', $receiver_node_id = null) {
    $pdo = getDbConnection($config);
    if (!$pdo) return false;
    
    $stmt = $pdo->prepare("
        INSERT INTO chat_messages (sender_node_id, receiver_node_id, message_type, content)
        VALUES (?, ?, ?, ?)
    ");
    
    return $stmt->execute([$sender_node_id, $receiver_node_id, $message_type, $content]);
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'get_nodes':
            $nodes = getOnlineNodes($config);
            echo json_encode(['success' => true, 'nodes' => $nodes]);
            exit;
            
        case 'get_apps':
            $category = $_POST['category'] ?? null;
            $search = $_POST['search'] ?? null;
            $apps = getAvailableApps($config, $category, $search);
            echo json_encode(['success' => true, 'apps' => $apps]);
            exit;
            
        case 'get_chat':
            $since_id = intval($_POST['since_id'] ?? 0);
            $node_id = $_SESSION['node_id'] ?? null;
            $messages = getChatMessages($config, $since_id, $node_id);
            echo json_encode(['success' => true, 'messages' => $messages]);
            exit;
            
        case 'send_chat':
            if (!isset($_SESSION['node_id'])) {
                echo json_encode(['success' => false, 'error' => 'Not authenticated']);
                exit;
            }
            
            $content = trim($_POST['content'] ?? '');
            $message_type = $_POST['message_type'] ?? 'broadcast';
            $receiver_id = $_POST['receiver_id'] ?? null;
            
            if (empty($content)) {
                echo json_encode(['success' => false, 'error' => 'Message cannot be empty']);
                exit;
            }
            
            $success = sendChatMessage($config, $_SESSION['node_id'], $content, $message_type, $receiver_id);
            echo json_encode(['success' => $success]);
            exit;
            
        case 'verify_app':
            $app_token = $_POST['app_token'] ?? '';
            $download_url = $_POST['download_url'] ?? '';
            
            if ($app_token && $download_url) {
                // Verify app hash
                $verify_url = str_replace('/grab?', '/verify?', $download_url) . "&token=" . $app_token;
                
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $verify_url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 10);
                $response = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                
                if ($http_code === 200) {
                    $verification = json_decode($response, true);
                    echo json_encode(['success' => true, 'verification' => $verification]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Verification failed']);
                }
            } else {
                echo json_encode(['success' => false, 'error' => 'Missing parameters']);
            }
            exit;
            
        default:
            echo json_encode(['success' => false, 'error' => 'Unknown action']);
            exit;
    }
}

// Check authentication
$authenticated = false;
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated']) {
    $authenticated = true;
} else {
    // Try to authenticate from headers
    $headers = getallheaders();
    if ($headers && authenticateNode($headers)) {
        $authenticated = true;
    }
}

// Handle invite links
$invite_data = null;
if (isset($_GET['invite'])) {
    try {
        $invite_json = base64_decode($_GET['invite']);
        $invite_data = json_decode($invite_json, true);
    } catch (Exception $e) {
        // Invalid invite link
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MonsterApps - P2P App Store</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🚀</text></svg>">
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            border-bottom: 1px solid #334155;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.5rem;
            font-weight: bold;
            color: #4ade80;
        }
        
        .status-bar {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 0.9rem;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            background: rgba(51, 65, 85, 0.5);
        }
        
        .status-online { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
        .status-offline { background: rgba(239, 68, 68, 0.2); color: #f87171; }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            border-bottom: 1px solid #334155;
        }
        
        .tab {
            padding: 1rem 1.5rem;
            background: none;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab:hover {
            color: #e2e8f0;
        }
        
        .tab.active {
            color: #4ade80;
            border-bottom-color: #4ade80;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .filters {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        
        .search-box {
            flex: 1;
            min-width: 300px;
            padding: 0.75rem;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            background: rgba(30, 41, 59, 0.5);
            color: #e2e8f0;
            font-size: 1rem;
        }
        
        .search-box:focus {
            outline: none;
            border-color: #4ade80;
        }
        
        .filter-select {
            padding: 0.75rem;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            background: rgba(30, 41, 59, 0.5);
            color: #e2e8f0;
            cursor: pointer;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }
        
        .card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 1rem;
            padding: 1.5rem;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            border-color: #4ade80;
        }
        
        .app-card {
            position: relative;
        }
        
        .app-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }
        
        .app-title {
            font-size: 1.25rem;
            font-weight: bold;
            color: #e2e8f0;
            margin-bottom: 0.25rem;
        }
        
        .app-meta {
            color: #94a3b8;
            font-size: 0.875rem;
        }
        
        .availability-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .available {
            background: rgba(34, 197, 94, 0.2);
            color: #4ade80;
        }
        
        .offline {
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
        }
        
        .app-stats {
            display: flex;
            gap: 1rem;
            margin: 1rem 0;
            font-size: 0.875rem;
            color: #94a3b8;
        }
        
        .download-btn {
            width: 100%;
            padding: 0.75rem;
            border: none;
            border-radius: 0.5rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 1rem;
        }
        
        .download-btn.available {
            background: #4ade80;
            color: #0f172a;
        }
        
        .download-btn.available:hover {
            background: #22c55e;
            transform: translateY(-1px);
        }
        
        .download-btn.offline {
            background: #374151;
            color: #6b7280;
            cursor: not-allowed;
        }
        
        .chat-container {
            height: 500px;
            display: flex;
            flex-direction: column;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 1rem;
            overflow: hidden;
        }
        
        .chat-messages {
            flex: 1;
            padding: 1rem;
            overflow-y: auto;
            border-bottom: 1px solid #334155;
        }
        
        .chat-message {
            margin-bottom: 1rem;
            padding: 0.75rem;
            border-radius: 0.5rem;
            background: rgba(30, 41, 59, 0.5);
        }
        
        .message-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
        }
        
        .message-sender {
            font-weight: bold;
            color: #4ade80;
        }
        
        .message-time {
            color: #94a3b8;
        }
        
        .message-content {
            color: #e2e8f0;
        }
        
        .chat-input {
            display: flex;
            padding: 1rem;
            gap: 1rem;
        }
        
        .chat-text {
            flex: 1;
            padding: 0.75rem;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            background: rgba(30, 41, 59, 0.5);
            color: #e2e8f0;
            resize: none;
        }
        
        .send-btn {
            padding: 0.75rem 1.5rem;
            background: #4ade80;
            color: #0f172a;
            border: none;
            border-radius: 0.5rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .send-btn:hover {
            background: #22c55e;
        }
        
        .node-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .node-card {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
        }
        
        .node-info {
            flex: 1;
        }
        
        .node-name {
            font-weight: bold;
            color: #e2e8f0;
        }
        
        .node-id {
            color: #94a3b8;
            font-size: 0.875rem;
            font-family: monospace;
        }
        
        .node-stats {
            display: flex;
            gap: 1rem;
            align-items: center;
            color: #94a3b8;
            font-size: 0.875rem;
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #94a3b8;
        }
        
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            color: #fca5a5;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .invite-banner {
            background: linear-gradient(135deg, #4ade80, #22c55e);
            color: #0f172a;
            padding: 1rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .invite-title {
            font-size: 1.25rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header-content {
                flex-direction: column;
                gap: 1rem;
            }
            
            .tabs {
                overflow-x: auto;
                white-space: nowrap;
            }
            
            .filters {
                flex-direction: column;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
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
                <?php if ($authenticated): ?>
                <div class="status-indicator status-online">
                    <span>✅</span>
                    <span><?= htmlspecialchars($_SESSION['username']) ?></span>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </header>

    <div class="container">
        <?php if ($invite_data): ?>
        <div class="invite-banner">
            <div class="invite-title">🎉 Network Invitation</div>
            <div>You've been invited to join <?= htmlspecialchars($invite_data['username']) ?>'s MonsterApps network!</div>
        </div>
        <?php endif; ?>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('store')">🛒 App Store</button>
            <button class="tab" onclick="switchTab('nodes')">🌐 Network Nodes</button>
            <button class="tab" onclick="switchTab('chat')">💬 Live Chat</button>
        </div>

        <!-- App Store Tab -->
        <div class="tab-content active" id="store-tab">
            <div class="filters">
                <input type="text" class="search-box" id="search-apps" placeholder="🔍 Search apps..." onkeyup="filterApps()">
                <select class="filter-select" id="category-filter" onchange="filterApps()">
                    <option value="All">All Categories</option>
                    <option value="Games">Games</option>
                    <option value="Utilities">Utilities</option>
                    <option value="Development">Development</option>
                    <option value="Graphics">Graphics</option>
                    <option value="Network">Network</option>
                    <option value="Business">Business</option>
                    <option value="Expansions">Expansions</option>
                </select>
            </div>
            <div class="grid" id="apps-grid">
                <div class="loading">Loading apps from network...</div>
            </div>
        </div>

        <!-- Network Nodes Tab -->
        <div class="tab-content" id="nodes-tab">
            <div class="node-list" id="nodes-list">
                <div class="loading">Loading network nodes...</div>
            </div>
        </div>

        <!-- Chat Tab -->
        <div class="tab-content" id="chat-tab">
            <div class="chat-container">
                <div class="chat-messages" id="chat-messages">
                    <div class="loading">Loading chat messages...</div>
                </div>
                <?php if ($authenticated): ?>
                <div class="chat-input">
                    <textarea class="chat-text" id="chat-input" placeholder="Type your message..." rows="2"></textarea>
                    <button class="send-btn" onclick="sendMessage()">Send</button>
                </div>
                <?php else: ?>
                <div style="padding: 1rem; text-align: center; color: #94a3b8;">
                    Connect your MonsterApps client to participate in chat
                </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Debug Tools Tab -->
        <div class="tab-content" id="debug-tab">
            <div style="margin-bottom: 2rem;">
                <h3 style="color: #4ade80; margin-bottom: 1rem;">🔧 Debug Tools</h3>
                <p style="color: #94a3b8; margin-bottom: 2rem;">
                    Use these tools to diagnose app verification and network issues.
                </p>
                
                <div style="display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap;">
                    <button onclick="refreshAllHashes()" style="padding: 0.75rem 1.5rem; background: #4ade80; color: #0f172a; border: none; border-radius: 0.5rem; font-weight: bold; cursor: pointer;">
                        🔄 Refresh All App Hashes
                    </button>
                    <button onclick="showDebugInfo()" style="padding: 0.75rem 1.5rem; background: #2196F3; color: white; border: none; border-radius: 0.5rem; font-weight: bold; cursor: pointer;">
                        📊 Show Debug Info
                    </button>
                    <button onclick="testConnections()" style="padding: 0.75rem 1.5rem; background: #FF9800; color: white; border: none; border-radius: 0.5rem; font-weight: bold; cursor: pointer;">
                        🌐 Test Node Connections
                    </button>
                </div>
                
                <div id="debug-output" style="background: rgba(15, 23, 42, 0.5); border-radius: 0.5rem; padding: 1rem; font-family: monospace; white-space: pre-wrap; min-height: 300px; max-height: 500px; overflow-y: auto; border: 1px solid #334155;">
                    Click a debug tool above to see results here...
                </div>
            </div>
        </div>
    </div>

    <script>
        let lastChatId = 0;
        let currentTab = 'store';
        let apps = [];
        let nodes = [];
        
        // Debug functions
        function refreshAllHashes() {
            const output = document.getElementById('debug-output');
            output.textContent = 'Refreshing app hashes...\n';
            
            // Try to refresh hashes on all online nodes
            nodes.forEach(node => {
                if (node.status === 'online') {
                    const refreshUrl = `http://${node.ip_address}:${node.webserver_port || 9001}/refresh_hashes`;
                    
                    fetch(refreshUrl)
                        .then(response => response.json())
                        .then(data => {
                            output.textContent += `\n${node.username} (${node.node_id.substring(0, 8)}...):\n`;
                            output.textContent += `  Updated: ${data.updated_count} apps\n`;
                            output.textContent += `  Total: ${data.total_apps} apps\n`;
                            if (data.errors.length > 0) {
                                output.textContent += `  Errors: ${data.errors.join(', ')}\n`;
                            }
                        })
                        .catch(error => {
                            output.textContent += `\n${node.username}: Error - ${error.message}\n`;
                        });
                }
            });
        }
        
        function showDebugInfo() {
            const output = document.getElementById('debug-output');
            output.textContent = 'Gathering debug information...\n';
            
            // Get debug info from all online nodes
            nodes.forEach(node => {
                if (node.status === 'online') {
                    const debugUrl = `http://${node.ip_address}:${node.webserver_port || 9001}/debug`;
                    
                    fetch(debugUrl)
                        .then(response => response.json())
                        .then(data => {
                            output.textContent += `\n=== ${node.username} (${node.node_id.substring(0, 8)}...) ===\n`;
                            output.textContent += `Server Status: ${data.server_status}\n`;
                            output.textContent += `Total Apps: ${data.total_apps}\n`;
                            output.textContent += `Web Server Port: ${data.web_server_port}\n\n`;
                            
                            if (data.apps && data.apps.length > 0) {
                                output.textContent += `Apps:\n`;
                                data.apps.forEach(app => {
                                    output.textContent += `  ${app.name}:\n`;
                                    output.textContent += `    Token: ${app.app_token}\n`;
                                    output.textContent += `    File Exists: ${app.file_exists}\n`;
                                    output.textContent += `    Size Match: ${app.size_match}\n`;
                                    output.textContent += `    Stored Size: ${app.stored_size} bytes\n`;
                                    output.textContent += `    Current Size: ${app.current_size} bytes\n`;
                                    output.textContent += `    Hash: ${app.stored_hash}\n\n`;
                                });
                            }
                        })
                        .catch(error => {
                            output.textContent += `\n${node.username}: Debug Error - ${error.message}\n`;
                        });
                }
            });
        }
        
        function testConnections() {
            const output = document.getElementById('debug-output');
            output.textContent = 'Testing node connections...\n';
            
            nodes.forEach(node => {
                const testUrl = `http://${node.ip_address}:${node.webserver_port || 9001}/status`;
                const startTime = Date.now();
                
                fetch(testUrl)
                    .then(response => response.json())
                    .then(data => {
                        const responseTime = Date.now() - startTime;
                        output.textContent += `\n${node.username}: ✅ Online (${responseTime}ms)\n`;
                        output.textContent += `  Apps Available: ${data.apps_available}\n`;
                        output.textContent += `  Node ID: ${data.node_id}\n`;
                    })
                    .catch(error => {
                        const responseTime = Date.now() - startTime;
                        output.textContent += `\n${node.username}: ❌ Failed (${responseTime}ms) - ${error.message}\n`;
                    });
            });
        }
        
        // Tab switching
        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(`${tabName}-tab`).classList.add('active');
            
            currentTab = tabName;
            
            // Load content
            if (tabName === 'store') {
                loadApps();
            } else if (tabName === 'nodes') {
                loadNodes();
            } else if (tabName === 'chat') {
                loadChat();
            } else if (tabName === 'debug') {
                // Debug tab doesn't need initial loading
                document.getElementById('debug-output').textContent = 'Debug tools ready. Click a button above to start.';
            }
        }
        
        // Load apps
        function loadApps() {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_apps'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    apps = data.apps;
                    displayApps(apps);
                } else {
                    showError('Failed to load apps');
                }
            })
            .catch(error => {
                console.error('Error loading apps:', error);
                showError('Network error loading apps');
            });
        }
        
        // Display apps
        function displayApps(appsToShow) {
            const grid = document.getElementById('apps-grid');
            
            if (appsToShow.length === 0) {
                grid.innerHTML = '<div class="loading">No apps available in the network</div>';
                return;
            }
            
            grid.innerHTML = appsToShow.map(app => `
                <div class="card app-card">
                    <div class="app-header">
                        <div>
                            <div class="app-title">${escapeHtml(app.app_name)}</div>
                            <div class="app-meta">by ${escapeHtml(app.username)} • ${escapeHtml(app.app_category)}</div>
                        </div>
                        <div class="availability-badge ${app.available ? 'available' : 'offline'}">
                            ${app.available ? '🟢 Online' : '🔴 Offline'}
                        </div>
                    </div>
                    <div class="app-stats">
                        <span>💾 ${formatFileSize(app.file_size)}</span>
                        <span>⬇️ Downloads: ${app.downloads || 0}</span>
                        <span>🕒 ${formatTimestamp(app.last_verified)}</span>
                    </div>
                    <button class="download-btn ${app.available ? 'available' : 'offline'}" 
                            onclick="downloadApp('${app.app_token}', '${app.download_url}', '${escapeHtml(app.app_name)}')"
                            ${!app.available ? 'disabled' : ''}>
                        ${app.available ? '⬇️ Download App' : '⏳ Node Offline'}
                    </button>
                </div>
            `).join('');
        }
        
        // Filter apps
        function filterApps() {
            const searchTerm = document.getElementById('search-apps').value.toLowerCase();
            const category = document.getElementById('category-filter').value;
            
            const filtered = apps.filter(app => {
                const matchesSearch = searchTerm === '' || 
                    app.app_name.toLowerCase().includes(searchTerm) ||
                    app.username.toLowerCase().includes(searchTerm);
                const matchesCategory = category === 'All' || app.app_category === category;
                
                return matchesSearch && matchesCategory;
            });
            
            displayApps(filtered);
        }
        
        // Download app
        function downloadApp(appToken, downloadUrl, appName) {
            // Show loading state
            const btn = event.target;
            const originalText = btn.textContent;
            btn.textContent = '🔄 Verifying...';
            btn.disabled = true;
            
            // Verify app first
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
                        // Verification passed - start download
                        btn.textContent = '⬇️ Downloading...';
                        window.open(downloadUrl, '_blank');
                        showNotification(`Downloading ${appName}...`, 'success');
                        
                        // Reset button after delay
                        setTimeout(() => {
                            btn.textContent = originalText;
                            btn.disabled = false;
                        }, 3000);
                    } else {
                        // Verification failed - show detailed error
                        console.error('Verification failed:', verification);
                        
                        let errorMsg = `App verification failed for ${appName}:\n\n`;
                        errorMsg += `Stored hash: ${verification.stored_hash}\n`;
                        errorMsg += `Current hash: ${verification.current_hash}\n`;
                        errorMsg += `File size: ${formatFileSize(verification.file_size)}\n`;
                        
                        if (verification.debug_info) {
                            errorMsg += `\nDebug info:\n`;
                            errorMsg += `File exists: ${verification.debug_info.file_exists || verification.file_exists}\n`;
                            errorMsg += `File path: ${verification.debug_info.file_path}\n`;
                        }
                        
                        errorMsg += `\nThe file may have been modified or corrupted.`;
                        
                        showNotification('App verification failed - see console for details', 'error');
                        alert(errorMsg);
                        
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
                console.error('Verification error:', error);
                showNotification('Failed to verify app before download', 'error');
                btn.textContent = originalText;
                btn.disabled = false;
            });
        }
        
        // Load nodes
        function loadNodes() {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_nodes'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    nodes = data.nodes;
                    displayNodes(nodes);
                    updateNodesCount(nodes.length);
                } else {
                    showError('Failed to load nodes');
                }
            })
            .catch(error => {
                console.error('Error loading nodes:', error);
                showError('Network error loading nodes');
            });
        }
        
        // Display nodes
        function displayNodes(nodesToShow) {
            const list = document.getElementById('nodes-list');
            
            if (nodesToShow.length === 0) {
                list.innerHTML = '<div class="loading">No nodes currently online</div>';
                return;
            }
            
            list.innerHTML = nodesToShow.map(node => `
                <div class="card node-card">
                    <div class="node-info">
                        <div class="node-name">${escapeHtml(node.username)}</div>
                        <div class="node-id">${node.node_id.substring(0, 16)}...</div>
                    </div>
                    <div class="node-stats">
                        <span class="status-indicator ${node.status === 'online' ? 'status-online' : 'status-offline'}">
                            ${node.status === 'online' ? '🟢' : '🔴'} ${node.status}
                        </span>
                        <span>📱 ${node.apps_count} apps</span>
                        <span>💬 ${node.chat_enabled ? 'Chat' : 'No Chat'}</span>
                        <span>🕒 ${node.seconds_ago}s ago</span>
                    </div>
                </div>
            `).join('');
        }
        
        // Load chat
        function loadChat() {
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=get_chat&since_id=${lastChatId}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayChatMessages(data.messages);
                    if (data.messages.length > 0) {
                        lastChatId = Math.max(...data.messages.map(m => m.id));
                    }
                }
            })
            .catch(error => {
                console.error('Error loading chat:', error);
            });
        }
        
        // Display chat messages
        function displayChatMessages(messages) {
            const chatContainer = document.getElementById('chat-messages');
            
            if (messages.length === 0 && lastChatId === 0) {
                chatContainer.innerHTML = '<div class="loading">No messages yet - start the conversation!</div>';
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
            
            // Scroll to bottom
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
        
        // Send chat message
        function sendMessage() {
            const input = document.getElementById('chat-input');
            const content = input.value.trim();
            
            if (!content) return;
            
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=send_chat&content=${encodeURIComponent(content)}&message_type=broadcast`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    input.value = '';
                    loadChat(); // Refresh chat
                } else {
                    showNotification('Failed to send message', 'error');
                }
            })
            .catch(error => {
                console.error('Error sending message:', error);
                showNotification('Network error sending message', 'error');
            });
        }
        
        // Utility functions
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatFileSize(bytes) {
            const sizes = ['B', 'KB', 'MB', 'GB'];
            if (bytes === 0) return '0 B';
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        function formatTimestamp(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        }
        
        function updateNodesCount(count) {
            document.getElementById('nodes-count').textContent = `${count} Nodes`;
        }
        
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
        
        function showError(message) {
            const container = document.querySelector('.container');
            const error = document.createElement('div');
            error.className = 'error';
            error.textContent = message;
            container.insertBefore(error, container.firstChild);
            
            setTimeout(() => error.remove(), 5000);
        }
        
        function showNotification(message, type) {
            // Simple notification system
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 1rem;
                border-radius: 0.5rem;
                color: white;
                z-index: 1000;
                background: ${type === 'success' ? '#22c55e' : '#ef4444'};
            `;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => notification.remove(), 3000);
        }
        
        // Auto-refresh
        function startAutoRefresh() {
            setInterval(() => {
                if (currentTab === 'store') {
                    loadApps();
                } else if (currentTab === 'nodes') {
                    loadNodes();
                } else if (currentTab === 'chat') {
                    loadChat();
                }
            }, <?= $config['chat_poll_interval'] ?>);
        }
        
        // Enter key for chat
        document.addEventListener('DOMContentLoaded', function() {
            const chatInput = document.getElementById('chat-input');
            if (chatInput) {
                chatInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendMessage();
                    }
                });
            }
            
            // Initial load
            loadApps();
            loadNodes();
            updateConnectionStatus(true);
            
            // Start auto-refresh
            startAutoRefresh();
        });
    </script>
</body>
</html>