<?php
// --- Configuration ---
define('DB_FILE', __DIR__ . '/board.db'); // Database file
define('UPLOADS_DIR', __DIR__ . '/uploads'); // Base Uploads directory
define('UPLOADS_URL_PATH', 'uploads'); // Relative web path base
define('MAX_FILE_SIZE', 20 * 1024 * 1024); // 20 MB
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'webm', 'mp3', 'wav', 'ogg', 'avi', 'mov', 'flv', 'wmv']);
define('VIDEO_EXTENSIONS', ['mp4', 'webm', 'avi', 'mov', 'flv', 'wmv']);
define('AUDIO_EXTENSIONS', ['mp3', 'wav', 'ogg']);

// Define allowed channels (UNCHANGED - Keep your existing list)
define('ALLOWED_CHANNELS', [ /* ... Your full list of channels ... */
  // Original
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'gif', 'h', 'hr', 'k', 'm', 'o', 'p', 'r', 's', 't', 'u', 'v',
  'vg', 'vm', 'vmg', 'vr', 'vrpg', 'vst', 'w', 'wg', 'i', 'ic', 'r9k', 's4s', 'vip', 'qa', 'cm',
  'hm', 'lgbt', 'mlp', 'news', 'out', 'po', 'pw', 'qst', 'sp', 'trv', 'tv', 'vp', 'wsg', 'wsr',
  'x', 'y', '3', 'aco', 'adv', 'an', 'bant', 'biz', 'cgl', 'ck', 'co', 'diy', 'fa', 'fit', 'gd',
  'hc', 'his', 'int', 'jp', 'lit', 'mu', 'n', 'pol', 'sci', 'soc', 'tg', 'toy', 'vt', 'xs',
  // New 40 Channels
  'art', 'tech', 'food', 'movies', 'music', 'books', 'news2', 'dev', 'meta', 'diy2', 'crypto', 'learn',
  'lang', 'travel2', 'health', 'cars', 'bikes', 'space', 'scifi', 'fantasy', 'hist2', 'phil', 'eco',
  'game', 'mobi', 'prog', 'web', 'desk', 'serv', 'net', 'sec', 'ai', 'ml', 'data', 'vr2', 'ar',
  'robot', 'drone', '3dp', 'hobby'
]);
define('CHANNEL_NAMES', [ /* ... Your full list of channel names ... */
  // Original
  'a' => 'Anime & Manga', 'b' => 'Random', 'c' => 'Anime/Cute', 'd' => 'Hentai/Alternative', 'e' => 'Ecchi',
  'f' => 'Flash', 'g' => 'Technology', 'gif' => 'Animated GIF', 'h' => 'Hentai', 'hr' => 'High Resolution',
  'k' => 'Weapons', 'm' => 'Mecha', 'o' => 'Auto', 'p' => 'Photography', 'r' => 'Adult Requests',
  's' => 'Sexy Beautiful Women', 't' => 'Torrents', 'u' => 'Yuri', 'v' => 'Video Games', 'vg' => 'Video Game Generals',
  'vm' => 'Video Games/Mobile', 'vmg' => 'Video Games/Mobile Generals', 'vr' => 'Retro Games',
  'vrpg' => 'Video Games/RPG', 'vst' => 'Video Games/Strategy', 'w' => 'Anime/Wallpapers',
  'wg' => 'Wallpapers/General', 'i' => 'Oekaki', 'ic' => 'Artwork/Critique', 'r9k' => 'ROBOT9001',
  's4s' => 'Shit 4chan Says', 'vip' => 'Very Important Posts', 'qa' => 'Question & Answer', 'cm' => 'Cute/Male',
  'hm' => 'Handsome Men', 'lgbt' => 'LGBT', 'mlp' => 'My Little Pony', 'news' => 'Current News',
  'out' => 'Outdoors', 'po' => 'Papercraft & Origami', 'pw' => 'Professional Wrestling',
  'qst' => 'Quests', 'sp' => 'Sports', 'trv' => 'Travel', 'tv' => 'Television & Film',
  'vp' => 'Pokemon', 'wsg' => 'Worksafe GIF', 'wsr' => 'Worksafe Requests', 'x' => 'Paranormal',
  'y' => 'Yaoi', '3' => '3DCG', 'aco' => 'Adult Cartoons', 'adv' => 'Advice', 'an' => 'Animals & Nature',
  'bant' => 'International/Random', 'biz' => 'Business & Finance', 'cgl' => 'Cosplay & EGL',
  'ck' => 'Food & Cooking', 'co' => 'Comics & Cartoons', 'diy' => 'Do-It-Yourself', 'fa' => 'Fashion',
  'fit' => 'Fitness', 'gd' => 'Graphic Design', 'hc' => 'Hardcore', 'his' => 'History & Humanities',
  'int' => 'International', 'jp' => 'Otaku Culture', 'lit' => 'Literature', 'mu' => 'Music',
  'n' => 'Transportation', 'pol' => 'Politically Incorrect', 'sci' => 'Science & Math', 'soc' => 'Social',
  'tg' => 'Traditional Games', 'toy' => 'Toys', 'vt' => 'Virtual YouTubers', 'xs' => 'Extreme Sports',
  // New 40 Channels
  'art' => 'Art General', 'tech' => 'Technology General', 'food' => 'Food General', 'movies' => 'Movies General',
  'music' => 'Music General', 'books' => 'Books General', 'news2' => 'News General', 'dev' => 'Development',
  'meta' => 'Meta/Board Talk', 'diy2' => 'DIY General', 'crypto' => 'Cryptocurrency', 'learn' => 'Learning & Education',
  'lang' => 'Languages', 'travel2' => 'Travel General', 'health' => 'Health & Wellness', 'cars' => 'Cars & Vehicles',
  'bikes' => 'Motorcycles', 'space' => 'Space & Astronomy', 'scifi' => 'Sci-Fi', 'fantasy' => 'Fantasy',
  'hist2' => 'History General', 'phil' => 'Philosophy', 'eco' => 'Economics', 'game' => 'Gaming General',
  'mobi' => 'Mobile Tech', 'prog' => 'Programming', 'web' => 'Web Development', 'desk' => 'Desktop Customization',
  'serv' => 'Servers & Hosting', 'net' => 'Networking', 'sec' => 'Security', 'ai' => 'Artificial Intelligence',
  'ml' => 'Machine Learning', 'data' => 'Data Science', 'vr2' => 'Virtual Reality General', 'ar' => 'Augmented Reality',
  'robot' => 'Robotics', 'drone' => 'Drones', '3dp' => '3D Printing', 'hobby' => 'Hobbies General'
]);
define('NSFW_CHANNELS', [ /* ... Your list ... */
  // Original
  'b', 'd', 'gif', 'h', 'hr', 'r9k', 's', 'soc', 'x', 'y', 'aco', 'bant', 'hc', 'hm', 'pol', 'r', 's4s', 'lgbt',
  // New (Add any relevant new ones here)
  'art', // Art can sometimes be NSFW
  'meta', // Meta discussions might touch on NSFW rules/topics
  'hist2', // History can contain sensitive/graphic content
]);
$channel_categories = [ /* ... Your categories ... */
  'Japanese Culture' => ['a', 'c', 'e', 'h', 'jp', 'm', 'u', 'w', 'vt'],
  'Video Games' => ['v', 'vg', 'vm', 'vmg', 'vr', 'vrpg', 'vst', 'vp', 'game'],
  'Creative' => ['i', 'ic', 'p', 'po', 'gd', 'diy', 'diy2', 'art', 'music', 'mu', 'lit', 'books', '3dp'],
  'Technology' => ['g', 'f', 'tech', 'dev', 'prog', 'web', 'serv', 'net', 'sec', 'ai', 'ml', 'data', 'mobi', 'crypto', 'sci', 'vr2', 'ar', 'robot', 'drone', 'space'],
  'Interests & Hobbies' => ['o', 'k', 'out', 'ck', 'food', 'sp', 'toy', 'n', 'cars', 'bikes', 'hobby', 'xs', 'trv', 'travel2', 'health', 'fit', 'fa', 'cgl', 'mlp', 'co', 'tv', 'movies', 'lang', 'learn'],
  'Adult (18+)' => ['s', 'd', 'gif', 'hr', 'r', 'wsr', 'y', '3', 'aco', 'hc', 'hm', 'cm'], // Use with caution & check local laws
  'Random & Community' => ['b', 'r9k', 's4s', 'vip', 'qa', 'adv', 'an', 'bant', 'int', 'news', 'news2', 'pol', 'soc', 'his', 'hist2', 'phil', 'eco', 'biz', 'lgbt', 'pw', 'qst', 'wsg', 'x', 'meta', 'desk'],
];

define('THREADS_PER_PAGE', 10);
define('REPLIES_PREVIEW_COUNT', 6);
define('COMMENT_PREVIEW_LENGTH', 1000);
define('USERNAME_MAX_LENGTH', 50);
define('PASSWORD_MIN_LENGTH', 6); // Added for registration

// User Roles
define('ROLE_USER', 'user');
define('ROLE_JANITOR', 'janitor');
define('ROLE_MODERATOR', 'moderator');
define('ROLE_ADMIN', 'admin');
$roles = [ROLE_USER, ROLE_JANITOR, ROLE_MODERATOR, ROLE_ADMIN]; // Define available roles

// User Statuses
define('STATUS_ACTIVE', 'active');
define('STATUS_BANNED', 'banned');
$statuses = [STATUS_ACTIVE, STATUS_BANNED];

// --- Initialization & DB Setup ---
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Configure session settings for better security (optional but recommended)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
  ini_set('session.cookie_secure', 1); // Use secure cookies if HTTPS is enabled
}
// ini_set('session.cookie_samesite', 'Lax'); // Or 'Strict'

// Start session AFTER setting configurations
if (session_status() === PHP_SESSION_NONE) {
  session_start();
}

// Regenerate session ID periodically to prevent fixation
if (!isset($_SESSION['last_regen']) || time() - $_SESSION['last_regen'] > (15 * 60)) { // Regenerate every 15 minutes
  session_regenerate_id(true);
  $_SESSION['last_regen'] = time();
}

// CSRF Token
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- Access Denied Page ---
if (isset($_GET['access']) && $_GET['access'] === 'denied') {
  http_response_code(403); // Forbidden
  echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied</title>
  <link rel="icon" type="image/png" href="/HDBoard.png">
  <style>
    body { background-color: #1a1a1a; color: #e0e0e0; font-family: sans-serif; text-align: center; padding-top: 50px; }
    .container { max-width: 600px; margin: auto; background-color: #282828; padding: 30px; border: 1px solid #444; border-radius: 5px; }
    h1 { color: #f7768e; }
    a { color: #7aa2f7; }
    a:hover { color: #c0caf5; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Access Denied</h1>
    <p>You do not have permission to perform this action or access this resource.</p>
    <p><a href="./">Return to Board Index</a></p>
  </div>
</body>
</html>
HTML;
  exit;
}

// --- Uploads Directory Check ---
if (!is_dir(UPLOADS_DIR)) {
  if (!mkdir(UPLOADS_DIR, 0775, true)) { die("Error: Could not create base uploads directory."); }
}
if (!is_writable(UPLOADS_DIR)) { die("Error: The base uploads directory is not writable."); }

// --- Database Connection and Schema Update ---
try {
  $db = new PDO('sqlite:' . DB_FILE);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
  // Enable Foreign Key support for SQLite
  $db->exec('PRAGMA foreign_keys = ON;');

  // --- NEW: Users Table ---
  $db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE, -- Usernames are case-insensitive unique
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '" . ROLE_USER . "', -- Default role is 'user'
    status TEXT NOT NULL DEFAULT '" . STATUS_ACTIVE . "', -- Default status is 'active'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK(role IN ('" . implode("','", $roles) . "')), -- Ensure role is valid
    CHECK(status IN ('" . implode("','", $statuses) . "')) -- Ensure status is valid
  )");

  // --- Update Threads Table ---
  $db->exec("CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    user_id INTEGER DEFAULT NULL,             -- NEW: Link to users table
    username TEXT DEFAULT NULL,             -- KEPT: For anonymous/legacy posts
    password_hash TEXT DEFAULT NULL,        -- KEPT: For legacy password checks
    subject TEXT,
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_reply_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL -- If user deleted, keep post but unlink
  )");

  // --- Update Replies Table ---
  $db->exec("CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    user_id INTEGER DEFAULT NULL,             -- NEW: Link to users table
    username TEXT DEFAULT NULL,             -- KEPT: For anonymous/legacy posts
    password_hash TEXT DEFAULT NULL,        -- KEPT: For legacy password checks
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL -- If user deleted, keep reply but unlink
  )");

  // Add columns if they don't exist (using helper function)
  function addColumnIfNotExists(PDO $db, string $tableName, string $columnName, string $columnDefinition) {
    try {
      $stmt = $db->query("PRAGMA table_info($tableName)");
      $columns = $stmt->fetchAll(PDO::FETCH_COLUMN, 1);
      if (!in_array($columnName, $columns)) {
        $db->exec("ALTER TABLE $tableName ADD COLUMN $columnName $columnDefinition");
        error_log("Added column '$columnName' to table '$tableName'.");
      }
    } catch (PDOException $e) {
      error_log("Schema Update Error (Table: $tableName, Column: $columnName): " . $e->getMessage());
      // Optionally display a warning, but don't die
      // echo "<p class='error'>Warning: Could not update database schema for column '{$columnName}'.</p>";
    }
  }

  // Check and add new columns/FKs
  addColumnIfNotExists($db, 'threads', 'user_id', 'INTEGER DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL');
  addColumnIfNotExists($db, 'replies', 'user_id', 'INTEGER DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL');
  // Keep checking for the old username/password columns for compatibility
  addColumnIfNotExists($db, 'threads', 'username', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'threads', 'password_hash', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'replies', 'username', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'replies', 'password_hash', 'TEXT DEFAULT NULL');
  // Add columns to users table if needed (though CREATE TABLE should handle it)
  addColumnIfNotExists($db, 'users', 'role', "TEXT NOT NULL DEFAULT '" . ROLE_USER . "' CHECK(role IN ('" . implode("','", $roles) . "'))");
  addColumnIfNotExists($db, 'users', 'status', "TEXT NOT NULL DEFAULT '" . STATUS_ACTIVE . "' CHECK(status IN ('" . implode("','", $statuses) . "'))");

} catch (PDOException $e) {
  error_log("Database Connection/Setup Error: " . $e->getMessage());
  die("Database Connection/Setup Error: " . $e->getMessage());
}

// --- Helper Functions ---

/**
 * Checks if a user is logged in.
 */
function is_logged_in(): bool {
  return isset($_SESSION['user_id']);
}

/**
 * Gets the current user's data from session.
 */
function get_current_user(): ?array {
  if (!is_logged_in()) {
    return null;
  }
  // Ensure essential data is present
  if (isset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['role'], $_SESSION['status'])) {
    return [
      'id' => $_SESSION['user_id'],
      'username' => $_SESSION['username'],
      'role' => $_SESSION['role'],
      'status' => $_SESSION['status'],
    ];
  }
  // If session data is incomplete, force logout
  logout_user();
  return null;
}

/**
 * Logs out the current user.
 */
function logout_user() {
  // Unset all session variables
  $_SESSION = array();

  // If it's desired to kill the session, also delete the session cookie.
  // Note: This will destroy the session, and not just the session data!
  if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
      $params["path"], $params["domain"],
      $params["secure"], $params["httponly"]
    );
  }

  // Finally, destroy the session.
  session_destroy();
}

/**
 * Checks if the current user has a specific role or higher (Admin > Moderator > Janitor > User).
 */
function user_has_role(string $required_role): bool {
  $user = get_current_user();
  if (!$user) return false;

  $role_hierarchy = [
    ROLE_USER => 1,
    ROLE_JANITOR => 2,
    ROLE_MODERATOR => 3,
    ROLE_ADMIN => 4
  ];

  $user_level = $role_hierarchy[$user['role']] ?? 0;
  $required_level = $role_hierarchy[$required_role] ?? 0;

  return $user_level >= $required_level;
}

/**
 * Verifies submitted password against the stored hash for a *legacy* username (stored directly in posts).
 * Searches both threads and replies for the FIRST post with a hash for that raw username.
 * IMPORTANT: This is for compatibility with posts made *before* the user table system.
 */
function verify_legacy_user_password(PDO $db, string $raw_username, string $submitted_password): bool {
  if (empty($raw_username) || empty($submitted_password)) {
    return false;
  }
  $existing_hash = null;
  try {
    // Find the hash from the earliest post (thread or reply) by this raw username where a hash is stored
    $stmt_check = $db->prepare("
      SELECT password_hash FROM (
        SELECT password_hash, created_at FROM threads WHERE username = ? COLLATE NOCASE AND password_hash IS NOT NULL AND user_id IS NULL
        UNION ALL
        SELECT password_hash, created_at FROM replies WHERE username = ? COLLATE NOCASE AND password_hash IS NOT NULL AND user_id IS NULL
      ) AS user_posts
      ORDER BY created_at ASC
      LIMIT 1
    ");
    $stmt_check->execute([$raw_username, $raw_username]);
    $result = $stmt_check->fetch();
    $existing_hash = $result ? $result['password_hash'] : null;

    if ($existing_hash === null) {
      // error_log("No legacy password hash found for raw username: " . $raw_username);
      return false; // Username not registered via legacy method or password not set
    }

    return password_verify($submitted_password, $existing_hash);

  } catch (PDOException $e) {
    error_log("Legacy password verification DB error for '{$raw_username}': " . $e->getMessage());
    return false; // DB error during check
  }
}

/**
 * Fetches user data by username.
 */
function get_user_by_username(PDO $db, string $username): ?array {
  try {
    $stmt = $db->prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE");
    $stmt->execute([$username]);
    return $stmt->fetch() ?: null;
  } catch (PDOException $e) {
    error_log("Error fetching user by username '{$username}': " . $e->getMessage());
    return null;
  }
}

/**
 * Fetches user data by ID.
 */
function get_user_by_id(PDO $db, int $user_id): ?array {
  try {
    $stmt = $db->prepare("SELECT id, username, role, status, created_at FROM users WHERE id = ?"); // Exclude password_hash
    $stmt->execute([$user_id]);
    return $stmt->fetch() ?: null;
  } catch (PDOException $e) {
    error_log("Error fetching user by ID '{$user_id}': " . $e->getMessage());
    return null;
  }
}

/**
 * Deletes the uploaded file associated with a post.
 */
function delete_post_file(?string $image_relative_path): bool {
  if (empty($image_relative_path)) {
    return true; // No file to delete
  }
  $full_path = UPLOADS_DIR . '/' . $image_relative_path;
  // Basic path validation to prevent traversal
  if (strpos($image_relative_path, '..') !== false || !file_exists($full_path)) {
    error_log("Attempted to delete invalid or non-existent file: " . $full_path);
    return false; // File not found or path seems invalid
  }
  if (is_writable($full_path)) {
    if (unlink($full_path)) {
      return true;
    } else {
      error_log("Failed to delete file: " . $full_path);
      return false;
    }
  } else {
    error_log("File not writable, cannot delete: " . $full_path);
    return false;
  }
}

// --- Standard Functions (handle_upload, get_render_media_type) ---
function handle_upload($file_input_name) {
  if (!isset($_FILES[$file_input_name]) || $_FILES[$file_input_name]['error'] === UPLOAD_ERR_NO_FILE) {
    return ['success' => false]; // No file uploaded
  }

  $file = $_FILES[$file_input_name];

  // --- Error Handling ---
  if ($file['error'] !== UPLOAD_ERR_OK) {
    switch ($file['error']) {
      case UPLOAD_ERR_INI_SIZE:
      case UPLOAD_ERR_FORM_SIZE:
        return ['error' => 'File is too large (Server limit).'];
      case UPLOAD_ERR_PARTIAL:
        return ['error' => 'File was only partially uploaded.'];
      case UPLOAD_ERR_NO_TMP_DIR:
        return ['error' => 'Missing temporary folder.'];
      case UPLOAD_ERR_CANT_WRITE:
        return ['error' => 'Failed to write file to disk.'];
      case UPLOAD_ERR_EXTENSION:
        return ['error' => 'A PHP extension stopped the upload.'];
      default:
        return ['error' => 'Unknown upload error (Code: ' . $file['error'] . ').'];
    }
  }
  if ($file['size'] > MAX_FILE_SIZE) {
    return ['error' => 'File is too large (Max: ' . (MAX_FILE_SIZE / 1024 / 1024) . ' MB).'];
  }

  // --- Extension Check ---
  $file_info = pathinfo($file['name']);
  $extension = strtolower($file_info['extension'] ?? '');
  if (!in_array($extension, ALLOWED_EXTENSIONS)) {
    return ['error' => 'Invalid file type. Allowed: ' . implode(', ', ALLOWED_EXTENSIONS)];
  }

  // --- Get Image Dimensions ---
  $img_w = null; $img_h = null;
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
    $image_size = @getimagesize($file['tmp_name']);
    if ($image_size !== false) {
      $img_w = $image_size[0] ?? null;
      $img_h = $image_size[1] ?? null;
    }
  }

  // --- Create Dated Subdirectory ---
  $year = date('Y'); $month = date('m'); $day = date('d');
  $relative_dir_path = $year . '/' . $month . '/' . $day;
  $target_dir = UPLOADS_DIR . '/' . $relative_dir_path;
  if (!is_dir($target_dir)) {
    if (!mkdir($target_dir, 0775, true)) {
      error_log("Error: Could not create dated upload directory: " . $target_dir);
      return ['error' => 'Server error: Could not create upload directory.'];
    }
  }
  if (!is_writable($target_dir)) { // Check the specific dated dir
    error_log("Error: Dated upload directory is not writable: " . $target_dir);
    return ['error' => 'Server error: Upload directory is not writable.'];
  }

  // --- Generate Filename and Destination ---
  $new_filename_base = uniqid() . time();
  $new_filename = $new_filename_base . '.' . $extension;
  $relative_path_for_db = $relative_dir_path . '/' . $new_filename;
  $destination = $target_dir . '/' . $new_filename;

  // --- Move File ---
  if (move_uploaded_file($file['tmp_name'], $destination)) {
    if (!file_exists($destination)) {
      error_log("Failed confirm uploaded file existence: " . $destination);
      return ['error' => 'Failed to confirm file after move.'];
    }
    return [ 'success' => true, 'filename' => $relative_path_for_db, 'orig_name' => basename($file['name']), 'width' => $img_w, 'height' => $img_h ];
  } else {
    error_log("Failed to move uploaded file to " . $destination);
    return ['error' => 'Failed to save uploaded file.'];
  }
}

function get_render_media_type($url_or_filename) {
  if (!$url_or_filename) return 'unknown';
  // YouTube check
  $youtube_regex = '/^https?:\/\/(?:www\.)?(?:m\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})(?:[?&].*)?$/i';
  if (preg_match($youtube_regex, $url_or_filename)) { return 'youtube'; }
  // Extension check
  $extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
  if (in_array($extension, VIDEO_EXTENSIONS)) return 'video';
  if (in_array($extension, AUDIO_EXTENSIONS)) return 'audio';
  // Local filename check
  if (!preg_match('/^https?:\/\//', $url_or_filename) && !preg_match('/^ftp:\/\//', $url_or_filename)) {
    $local_extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
    if (in_array($local_extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
    if (in_array($local_extension, VIDEO_EXTENSIONS)) return 'video';
    if (in_array($local_extension, AUDIO_EXTENSIONS)) return 'audio';
  }
  return 'unknown';
}

// --- UPDATED format_comment with BBCode ---
function format_comment($comment) {
  $comment = (string) ($comment ?? '');

  // 1. Sanitize HTML initially to prevent HTML injection via BBCode attributes
  $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');

  // 2. BBCode to HTML Conversion
  $comment = preg_replace('/\[b\](.*?)\[\/b\]/is', '<strong>$1</strong>', $comment);
  $comment = preg_replace('/\[i\](.*?)\[\/i\]/is', '<em>$1</em>', $comment);
  $comment = preg_replace('/\[u\](.*?)\[\/u\]/is', '<u>$1</u>', $comment);
  $comment = preg_replace('/\[s\](.*?)\[\/s\]/is', '<del>$1</del>', $comment);
  $comment = preg_replace('/\[spoiler\](.*?)\[\/spoiler\]/is', '<span class="spoiler">$1</span>', $comment);
  $comment = preg_replace_callback('/\[code\](.*?)\[\/code\]/is', function ($matches) {
    $code_content = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
    $code_content_nl = nl2br($code_content, false);
    return '<pre class="code-block"><code>' . $code_content_nl . '</code></pre>';
  }, $comment);
  $comment = preg_replace('/\[quote\](.*?)\[\/quote\]/is', '<blockquote class="quote-block">$1</blockquote>', $comment);
  $comment = preg_replace('/\[quote=(?:&quot;)?(.*?)(?:&quot;)?\](.*?)\[\/quote\]/is', '<blockquote class="quote-block"><cite>Quote from $1:</cite>$2</blockquote>', $comment);

  // 3. Linkify URLs (AFTER BBCode)
  $comment = preg_replace_callback(
    '/(?<![\'"])(?<![=\/])\b(https?|ftp):\/\/([^\s<>"\'`]+)/i',
    function ($matches) {
      $url = $matches[0];
      $decoded_display = htmlspecialchars_decode($matches[2], ENT_QUOTES);
      $display_url = (mb_strlen($decoded_display) > 50) ? mb_substr($decoded_display, 0, 47) . '...' : $decoded_display;
      $safe_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
      return '<a href="' . $safe_url . '" target="_blank" rel="noopener noreferrer">' . htmlspecialchars(urldecode($matches[1] . '://' . $display_url), ENT_QUOTES, 'UTF-8') . '</a>';
    },
    $comment
  );

  // 4. nl2br (AFTER block tags)
  $comment = nl2br($comment, false);

  // 5. Greentext (after nl2br)
  $comment = preg_replace('/(^<br\s*\/?>|\n|^)(>[^<].*?)$/m', '$1<span class="greentext">$2</span>', $comment);
  $comment = preg_replace('/(^\s*)(>[^<].*?)$/m', '$1<span class="greentext">$2</span>', $comment);

  // 6. Reply Links (>>123)
  $comment = preg_replace('/>>(\d+)/', '<a href="#post-$1" class="reply-mention">>>$1</a>', $comment);

  return $comment;
}

// --- process_comment_media_links ---
function process_comment_media_links($text, $post_element_id) {
  $media_html = '';
  $cleaned_text = $text;
  $link_counter = 0;
  $url_regex = '/(?<!src=["\'])(?<!href=["\'])(?<!data-media-url=["\'])\b(https?|ftp):\/\/[^\s<>"]+/i';

  if (preg_match_all($url_regex, $text, $matches, PREG_OFFSET_CAPTURE)) {
    $matches_reversed = array_reverse($matches[0]);
    $media_items_to_append = [];
    foreach ($matches_reversed as $match) {
      $url = $match[0]; $offset = $match[1];
      $render_type = get_render_media_type($url);
      if ($render_type !== 'unknown') {
        $media_items_to_append[] = ['url' => $url, 'render_type' => $render_type];
        $cleaned_text = mb_substr($cleaned_text, 0, $offset) . mb_substr($cleaned_text, $offset + mb_strlen($url));
      }
    }
    foreach (array_reverse($media_items_to_append) as $item) {
      $link_counter++;
      $media_id = $post_element_id . '-link-' . $link_counter;
      $safe_url = htmlspecialchars($item['url'], ENT_QUOTES, 'UTF-8');
      $render_type = $item['render_type'];
      $button_text = 'View Media';
      if ($render_type === 'image') $button_text = 'View Image';
      elseif ($render_type === 'video') $button_text = 'View Video';
      elseif ($render_type === 'audio') $button_text = 'View Audio';
      elseif ($render_type === 'youtube') $button_text = 'View YouTube';
      $media_html .= "<div class='file-info comment-link-info'><div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_id}' data-media-url='{$safe_url}' data-media-type='{$render_type}'>{$button_text}</button></div><span class='file-details'>Link: <a href='{$safe_url}' target='_blank' rel='noopener noreferrer'>{$safe_url}</a></span></div><div id='media-container-{$media_id}' class='media-container' style='display:none;'></div>";
    }
  }
  return ['cleaned_text' => trim($cleaned_text), 'media_html' => $media_html];
}

// --- Determine Current View ---
$show_board_index = true;
$current_channel_code = null;
$current_channel_display_name = 'Board Index';
$requested_channel = $_GET['channel'] ?? null;
if ($requested_channel !== null && in_array($requested_channel, ALLOWED_CHANNELS)) {
  $current_channel_code = $requested_channel;
  $current_channel_display_name = CHANNEL_NAMES[$current_channel_code] ?? $current_channel_code;
  $show_board_index = false;
}
$viewing_thread_id = null;
if (!$show_board_index) {
  $viewing_thread_id = filter_input(INPUT_GET, 'thread', FILTER_VALIDATE_INT);
  if ($viewing_thread_id === false || $viewing_thread_id === null) { $viewing_thread_id = null; }
}

// Determine if showing auth pages
$show_login_form = isset($_GET['action']) && $_GET['action'] === 'login';
$show_register_form = isset($_GET['action']) && $_GET['action'] === 'register';

// --- Global Variables for Actions/Messages ---
$action_error = null;
$action_success = null;
$auth_error = null; // Specific errors for login/register
$auth_success = null;
$show_action_form = null;
$post_data_for_form = null;

// --- Handle AUTH Actions (Login, Logout, Register) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
  $action = $_POST['action'];

  // CSRF Check for Auth actions
  $submitted_csrf = $_POST['csrf_token'] ?? null;
  if (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf)) {
    $auth_error = "Invalid form submission (CSRF). Please try again.";
    if ($action === 'dologin') $show_login_form = true;
    if ($action === 'doregister') $show_register_form = true;
    $action = null; // Prevent further processing for this request
  }

  switch ($action) {
    case 'dologin':
      $username = trim($_POST['username'] ?? '');
      $password = $_POST['password'] ?? '';

      if (empty($username) || empty($password)) {
        $auth_error = "Username and password are required.";
        $show_login_form = true;
      } else {
        $user = get_user_by_username($db, $username);

        if ($user && password_verify($password, $user['password_hash'])) {
          if ($user['status'] === STATUS_BANNED) {
            $auth_error = "This account is banned.";
            $show_login_form = true;
          } else {
            // Login successful! Regenerate session ID.
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['status'] = $user['status'];
            $_SESSION['last_regen'] = time(); // Reset regen timer
            $auth_success = "Login successful. Welcome, " . htmlspecialchars($user['username']) . "!";
            header("Location: ./"); // Redirect immediately
            exit;
          }
        } else {
          $auth_error = "Invalid username or password.";
          $show_login_form = true;
        }
      }
      break;

    case 'doregister':
      $username = trim($_POST['username'] ?? '');
      $password = $_POST['password'] ?? '';
      $password_confirm = $_POST['password_confirm'] ?? '';

      // Validation
      if (empty($username) || empty($password) || empty($password_confirm)) {
        $auth_error = "All fields are required for registration.";
      } elseif ($password !== $password_confirm) {
        $auth_error = "Passwords do not match.";
      } elseif (mb_strlen($password) < PASSWORD_MIN_LENGTH) {
        $auth_error = "Password must be at least " . PASSWORD_MIN_LENGTH . " characters long.";
      } elseif (mb_strlen($username) > USERNAME_MAX_LENGTH) {
        $auth_error = "Username is too long (max " . USERNAME_MAX_LENGTH . " characters).";
      } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        $auth_error = "Username can only contain letters, numbers, and underscores.";
      } else {
        $existing_user = get_user_by_username($db, $username);
        if ($existing_user) {
          $auth_error = "Username already taken. Please choose another.";
        } else {
          $password_hash = password_hash($password, PASSWORD_DEFAULT);
          if ($password_hash === false) {
            $auth_error = "Error processing password.";
            error_log("password_hash failed for registration attempt: " . $username);
          } else {
            try {
              $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
              $stmt->execute([$username, $password_hash]);
              $user_id = $db->lastInsertId();

              // Auto-login the user
              session_regenerate_id(true);
              $_SESSION['user_id'] = $user_id;
              $_SESSION['username'] = $username;
              $_SESSION['role'] = ROLE_USER; // Default role
              $_SESSION['status'] = STATUS_ACTIVE; // Default status
              $_SESSION['last_regen'] = time();

              $auth_success = "Registration successful! You are now logged in as " . htmlspecialchars($username) . ".";
              header("Location: ./");
              exit;
            } catch (PDOException $e) {
              if ($e->getCode() == 23000 || str_contains($e->getMessage(), 'UNIQUE constraint failed')) {
                $auth_error = "Username already taken (database constraint).";
              } else {
                $auth_error = "Database error during registration.";
                error_log("Registration DB error for '{$username}': " . $e->getMessage());
              }
            }
          }
        }
      }
      // Re-show form on error
      if ($auth_error) {
        $show_register_form = true;
      }
      break;

    case 'logout':
      logout_user();
      $auth_success = "You have been logged out.";
      header("Location: ./?loggedout=1");
      exit;
      break;

    case 'ban_user':
    case 'unban_user':
      if (!user_has_role(ROLE_MODERATOR)) {
        header("Location: ./?access=denied&error=perm"); exit;
      }
      $user_id_to_modify = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
      if (!$user_id_to_modify) {
        $action_error = "Invalid user ID specified for banning/unbanning.";
      } else {
        $target_user = get_user_by_id($db, $user_id_to_modify);
        if (!$target_user) {
          $action_error = "User to modify not found.";
        } elseif ($target_user['role'] === ROLE_ADMIN && !user_has_role(ROLE_ADMIN)) {
          $action_error = "You cannot modify an administrator account.";
        } else {
          $new_status = ($action === 'ban_user') ? STATUS_BANNED : STATUS_ACTIVE;
          $action_verb = ($action === 'ban_user') ? 'banned' : 'unbanned';
          try {
            $stmt = $db->prepare("UPDATE users SET status = ? WHERE id = ?");
            $stmt->execute([$new_status, $user_id_to_modify]);
            $action_success = "User '" . htmlspecialchars($target_user['username']) . "' has been " . $action_verb . ".";
            // Redirect back. Determine source page if possible, otherwise home.
            $referer = $_SERVER['HTTP_REFERER'] ?? './'; // Basic referer check
            header("Location: " . $referer . (strpos($referer, '?') ? '&' : '?') . "user_" . $action_verb . "=" . $user_id_to_modify);
            exit;
          } catch (PDOException $e) {
            $action_error = "Database error updating user status.";
            error_log("Error " . $action_verb . " user {$user_id_to_modify}: " . $e->getMessage());
          }
        }
      }
      break;
  }
}

// --- Handle Actions (Delete/Edit) - MODIFIED for Roles/Permissions ---
if (isset($_REQUEST['action']) && !in_array($_REQUEST['action'], ['login', 'register', 'dologin', 'doregister', 'logout', 'ban_user', 'unban_user'])) {
  $action = $_REQUEST['action'];
  // --- FIX: Replace INPUT_REQUEST ---
  $post_type_raw = $_REQUEST['type'] ?? null;
  $post_id_raw = $_REQUEST['id'] ?? null;
  $post_type = $post_type_raw ? filter_var($post_type_raw, FILTER_SANITIZE_SPECIAL_CHARS) : null;
  $post_id = $post_id_raw ? filter_var($post_id_raw, FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE) : null;
  // --- END FIX ---

  $submitted_password = $_POST['password'] ?? null;
  $submitted_csrf = $_POST['csrf_token'] ?? null;
  $current_user = get_current_user(); // Get logged in user data

  // Basic validation
  if (!in_array($post_type, ['thread', 'reply']) || !$post_id) {
    $action_error = "Invalid request parameters.";
  } elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf))) {
    error_log("CSRF token mismatch for action: " . $action);
    header("Location: ./?access=denied&error=csrf"); exit;
  } else {
    // Fetch the post data including user_id and legacy username/hash
    $post_data = null;
    try {
      if ($post_type === 'thread') {
        $stmt = $db->prepare("SELECT t.*, u.username as registered_username, u.status as user_status
                              FROM threads t
                              LEFT JOIN users u ON t.user_id = u.id
                              WHERE t.id = ?");
      } else { // reply
        $stmt = $db->prepare("SELECT r.*, t.channel, r.thread_id, u.username as registered_username, u.status as user_status
                              FROM replies r
                              JOIN threads t ON r.thread_id = t.id
                              LEFT JOIN users u ON r.user_id = u.id
                              WHERE r.id = ?");
      }
      $stmt->execute([$post_id]);
      $post_data = $stmt->fetch();
    } catch (PDOException $e) {
      error_log("DB Error fetching post for action {$action}: " . $e->getMessage());
      $action_error = "Database error fetching post details.";
    }

    if (!$post_data) {
      $action_error = ucfirst($post_type) . " not found.";
    } else {
      // Determine post ownership and authorization
      $is_own_post = $current_user && isset($post_data['user_id']) && $post_data['user_id'] == $current_user['id'];
      $can_moderate = user_has_role(ROLE_JANITOR); // Janitor+ can delete
      $can_edit = $is_own_post || user_has_role(ROLE_MODERATOR); // Owner or Mod+ can edit
      $can_delete = $is_own_post || $can_moderate; // Owners or staff can delete

      // Get display username (prioritize registered, fallback to legacy)
      $post_owner_display_name = $post_data['registered_username'] ?? $post_data['username'] ?? 'Anonymous';
      $post_owner_user_id = $post_data['user_id'] ?? null;
      $post_legacy_username = $post_data['username'] ?? null; // Raw username stored in post (if any)
      $post_channel = $post_data['channel'];
      $redirect_url_base = "./?channel=" . urlencode($post_channel);
      $redirect_url_thread = ($post_type === 'reply' && isset($post_data['thread_id'])) ? $redirect_url_base . "&thread=" . $post_data['thread_id'] : $redirect_url_base;

      // --- Permission Check before proceeding ---
      $require_password = false;
      $needs_permission_check = true; // Assume check needed unless action handles it

      switch ($action) {
        // --- DELETE ---
        case 'confirm_delete':
          if (!$can_delete) {
            header("Location: ./?access=denied&error=perm_delete"); exit;
          }
          $is_legacy_post = !$post_owner_user_id && !empty($post_legacy_username);
          $require_password = $is_legacy_post && !$current_user; // Only require pass if anon legacy

          $show_action_form = 'delete_confirm';
          $post_data_for_form = $post_data;
          $post_data_for_form['type'] = $post_type;
          $post_data_for_form['require_password'] = $require_password;
          $needs_permission_check = false;
          break;

        case 'delete': // Process deletion (POST)
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("Location: ./?access=denied&error=method"); exit; }
          if (!$can_delete) { header("Location: ./?access=denied&error=perm_delete"); exit; }

          $is_legacy_post = !$post_owner_user_id && !empty($post_legacy_username);
          $require_password = $is_legacy_post && !$current_user;
          $password_ok = true;

          if ($require_password && $post_legacy_username !== null) { // Added null check
            if (!verify_legacy_user_password($db, $post_legacy_username, $submitted_password)) {
              $password_ok = false;
              $action_error = "Incorrect password for legacy post.";
              $show_action_form = 'delete_confirm';
              $post_data_for_form = $post_data;
              $post_data_for_form['type'] = $post_type;
              $post_data_for_form['require_password'] = $require_password;
            }
          }

          if ($password_ok) {
            try {
              $db->beginTransaction();
              delete_post_file($post_data['image'] ?? null); // Attempt file deletion

              if ($post_type === 'thread') {
                $stmt_del = $db->prepare("DELETE FROM threads WHERE id = ?");
              } else {
                $stmt_del = $db->prepare("DELETE FROM replies WHERE id = ?");
              }
              $stmt_del->execute([$post_id]);
              $db->commit();
              $action_success = ucfirst($post_type) . " deleted successfully.";
              header("Location: " . $redirect_url_thread . "&deleted=" . $post_id); exit;
            } catch (PDOException $e) {
              if ($db->inTransaction()) $db->rollBack();
              error_log("DB Error deleting {$post_type} ID {$post_id}: " . $e->getMessage());
              $action_error = "Database error during deletion.";
            }
          }
          $needs_permission_check = false;
          break;

        // --- EDIT ---
        case 'show_edit_form':
          if (!$can_edit) {
            header("Location: ./?access=denied&error=perm_edit"); exit;
          }
          $is_legacy_post = !$post_owner_user_id && !empty($post_legacy_username);
          $require_password = $is_legacy_post && !$current_user;

          if ($require_password) {
            $show_action_form = 'edit_confirm';
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type;
          } else {
            // Staff or logged-in owner: Skip password
            $_SESSION['edit_verified'] = ['type' => $post_type, 'id' => $post_id, 'time' => time()];
            $show_action_form = 'edit_fields';
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type;
          }
          $needs_permission_check = false;
          break;

        case 'edit': // Process password verification for legacy edits (POST from confirm form)
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("Location: ./?access=denied&error=method"); exit; }

          $is_legacy_post = !$post_owner_user_id && !empty($post_legacy_username);
          if (!$is_legacy_post || $current_user) {
            header("Location: ./?access=denied&error=state"); exit; // Should not happen
          }

          if ($post_legacy_username !== null && verify_legacy_user_password($db, $post_legacy_username, $submitted_password)) { // Added null check
            $_SESSION['edit_verified'] = ['type' => $post_type, 'id' => $post_id, 'time' => time()];
            $show_action_form = 'edit_fields';
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type;
          } else {
            $action_error = "Incorrect password for legacy post.";
            $show_action_form = 'edit_confirm';
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type;
          }
          $needs_permission_check = false;
          break;

        case 'save_edit': // Process the submitted edit form (POST)
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("Location: ./?access=denied&error=method"); exit; }

          if (
            empty($_SESSION['edit_verified']) ||
            $_SESSION['edit_verified']['type'] !== $post_type ||
            $_SESSION['edit_verified']['id'] !== $post_id ||
            (time() - $_SESSION['edit_verified']['time'] > 300) // 5 min timeout
          ) {
            unset($_SESSION['edit_verified']);
            error_log("Edit verification failed or timed out for {$post_type} ID {$post_id}");
            header("Location: ./?access=denied&error=timeout"); exit;
          }

          if (!$can_edit) { // Double-check permission
            unset($_SESSION['edit_verified']);
            header("Location: ./?access=denied&error=perm_edit_save"); exit;
          }

          $new_comment = trim($_POST['comment'] ?? '');
          $new_subject = ($post_type === 'thread') ? trim($_POST['subject'] ?? '') : null;

          if (empty($new_comment)) { $action_error = "Comment cannot be empty."; }
          elseif (mb_strlen($new_comment) > 4000) { $action_error = "Post content is too long (max 4000 characters)."; }

          if ($action_error) {
            $show_action_form = 'edit_fields';
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type;
            $post_data_for_form['comment_attempt'] = $new_comment;
            $post_data_for_form['subject_attempt'] = $new_subject;
          } else {
            try {
              if ($post_type === 'thread') {
                $stmt_update = $db->prepare("UPDATE threads SET subject = ?, comment = ? WHERE id = ?");
                $stmt_update->execute([$new_subject, $new_comment, $post_id]);
              } else {
                $stmt_update = $db->prepare("UPDATE replies SET comment = ? WHERE id = ?");
                $stmt_update->execute([$new_comment, $post_id]);
              }
              unset($_SESSION['edit_verified']); // Clear flag
              $action_success = ucfirst($post_type) . " updated successfully.";
              $post_anchor = "#post-" . $post_id;
              header("Location: " . $redirect_url_thread . "&edited=" . $post_id . $post_anchor); exit;
            } catch (PDOException $e) {
              error_log("DB Error updating {$post_type} ID {$post_id}: " . $e->getMessage());
              $action_error = "Database error during update.";
              unset($_SESSION['edit_verified']);
            }
          }
          $needs_permission_check = false;
          break;

        default:
          $action_error = "Unknown action specified.";
          $needs_permission_check = false;
      }

      // Fallback permission check
      if ($needs_permission_check) {
        header("Location: ./?access=denied&error=perm_unknown"); exit;
      }
    }
  }
}

// --- Handle Post Request (New Thread/Reply) - MODIFIED for Users ---
$post_error = null;
$post_success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action']) && !$show_board_index && isset($_POST['comment']) && empty($action_error) && empty($show_action_form) && !$show_login_form && !$show_register_form) {
  $submitted_csrf = $_POST['csrf_token'] ?? null;
  if (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf)) {
    $post_error = "Invalid form submission. Please try again.";
  } else {

    $comment_raw = trim($_POST['comment'] ?? '');
    $subject = trim($_POST['subject'] ?? '');
    $thread_id = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT) ?: null;
    $posted_channel_code = trim($_POST['channel'] ?? '');
    $current_user = get_current_user();

    // Validation
    if (empty($posted_channel_code) || $posted_channel_code !== $current_channel_code) {
      $post_error = "Invalid channel specified for post.";
    } elseif ($current_user && $current_user['status'] === STATUS_BANNED) {
      $post_error = "Your account is banned and cannot post.";
    }

    // Determine User Identity for the Post
    $post_user_id = null;
    $post_username = null; // Legacy username field
    $post_password_hash = null; // Legacy password hash field

    if ($post_error === null) {
      if ($current_user) {
        // Logged-in User
        $post_user_id = $current_user['id'];
      } else {
        // Anonymous or Legacy User
        $input_username = trim($_POST['username'] ?? '');
        $input_password = $_POST['password'] ?? '';

        if (mb_strlen($input_username) > USERNAME_MAX_LENGTH) {
          $post_error = "Username is too long (max " . USERNAME_MAX_LENGTH . " characters).";
        } elseif (!empty($input_username)) {
          $existing_registered_user = get_user_by_username($db, $input_username);
          if ($existing_registered_user) {
            $post_error = "Username '" . htmlspecialchars($input_username) . "' is registered. Please log in to post.";
          } else {
            // Treat as legacy username
            $post_username = $input_username;
            $is_legacy_registered = false;
            try {
              $stmt_legacy_check = $db->prepare("
                SELECT 1 FROM (
                  SELECT 1 FROM threads WHERE username = ? COLLATE NOCASE AND password_hash IS NOT NULL AND user_id IS NULL
                  UNION ALL
                  SELECT 1 FROM replies WHERE username = ? COLLATE NOCASE AND password_hash IS NOT NULL AND user_id IS NULL
                ) LIMIT 1
              ");
              $stmt_legacy_check->execute([$input_username, $input_username]);
              if ($stmt_legacy_check->fetch()) {
                $is_legacy_registered = true;
              }
            } catch (PDOException $e) {
              error_log("Legacy username check failed for '{$input_username}': " . $e->getMessage());
              $post_error = "Database error during legacy username check.";
            }

            if ($post_error === null) {
              if ($is_legacy_registered) {
                if (empty($input_password)) {
                  $post_error = "Password required for legacy username '" . htmlspecialchars($input_username) . "'.";
                } elseif (!verify_legacy_user_password($db, $input_username, $input_password)) {
                  $post_error = "Invalid password for legacy username '" . htmlspecialchars($input_username) . "'.";
                }
                $post_password_hash = null; // Do NOT store hash again
              } else {
                // First time using this raw username
                if (!empty($input_password)) {
                  $post_password_hash = password_hash($input_password, PASSWORD_DEFAULT);
                  if ($post_password_hash === false) {
                    $post_error = "Failed to process password for legacy registration.";
                    error_log("password_hash() failed during legacy registration for '{$input_username}'.");
                  }
                } else {
                  $post_password_hash = null;
                }
              }
            }
          }
        } else {
          // Fully anonymous post
          $post_user_id = null;
          $post_username = null;
          $post_password_hash = null;
        }
      }
    } // End user identity determination

    // Continue Validation (Channel, Content)
    if ($post_error === null) {
      if ($thread_id) {
        try {
          $stmt_check_thread_channel = $db->prepare("SELECT channel FROM threads WHERE id = ?");
          $stmt_check_thread_channel->execute([$thread_id]);
          $thread_channel_data = $stmt_check_thread_channel->fetch();
          if (!$thread_channel_data) { $post_error = "Thread not found."; }
          elseif ($thread_channel_data['channel'] !== $current_channel_code) { $post_error = "Replying to a thread from the wrong channel page."; }
        } catch (PDOException $e) { $post_error = "Database error verifying thread."; }
      }

      if ($post_error === null) {
        $temp_media_check = process_comment_media_links($comment_raw, 'temp-validation');
        $has_text_content = !empty(trim($temp_media_check['cleaned_text']));
        $has_media_links = !empty($temp_media_check['media_html']);
        $has_file = isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE;

        if (!$thread_id && !$has_text_content && !$has_file && !$has_media_links) { $post_error = "Comment, file, or media link required for new thread."; }
        elseif ($thread_id && !$has_text_content && !$has_file && !$has_media_links) { $post_error = "Comment, file, or media link required for reply."; }
        elseif (mb_strlen($comment_raw) > 4000) { $post_error = "Post content is too long (max 4000 characters)."; }
        else {
          // Handle file upload
          $upload_result = handle_upload('image');
          if (isset($upload_result['error'])) { $post_error = $upload_result['error']; }
          else {
            // Insert into DB
            try {
              $db->beginTransaction();
              $image_path = $upload_result['filename'] ?? null;
              $image_orig = $upload_result['orig_name'] ?? null;
              $image_w = $upload_result['width'] ?? null;
              $image_h = $upload_result['height'] ?? null;

              if ($image_path === null && !$has_text_content && !$has_media_links) {
                $db->rollBack();
                $post_error = "Comment, file, or media link required.";
              } else {
                if ($thread_id) { // Reply
                  $stmt = $db->prepare("INSERT INTO replies (thread_id, user_id, username, password_hash, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                  $stmt->execute([ $thread_id, $post_user_id, $post_username, $post_password_hash, $comment_raw, $image_path, $image_orig, $image_w, $image_h ]);
                  $new_post_id = $db->lastInsertId();
                  $stmt_update = $db->prepare("UPDATE threads SET last_reply_at = CURRENT_TIMESTAMP WHERE id = ?");
                  $stmt_update->execute([$thread_id]);
                  $db->commit();
                  header("Location: ./?channel=" . urlencode($current_channel_code) . "&thread=" . $thread_id . "&ts=" . time() . "#post-" . $new_post_id); exit;
                } else { // New Thread
                  $stmt = $db->prepare("INSERT INTO threads (channel, user_id, username, password_hash, subject, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                  $stmt->execute([ $current_channel_code, $post_user_id, $post_username, $post_password_hash, $subject, $comment_raw, $image_path, $image_orig, $image_w, $image_h ]);
                  $new_post_id = $db->lastInsertId();
                  $db->commit();
                  header("Location: ./?channel=" . urlencode($current_channel_code) . "&newthread=" . $new_post_id . "&ts=" . time()); exit;
                }
              }
            } catch (PDOException $e) {
              if ($db->inTransaction()) $db->rollBack();
              error_log("Database Post Error: " . $e->getMessage());
              $post_error = "Database Error: Could not save post.";
            }
          }
        }
      }
    }
  }
}

// --- Fetch Data for Display ---
$threads = [];
$replies_to_display = [];
$reply_counts = [];
$total_threads = 0;
$total_pages = 1;
$thread_op = null;
$current_page = 1;
$board_index_data = [];
$users_data = []; // To store fetched user data for posts

// Only fetch page data if not showing an auth form or an action form that prevents it
$fetch_page_data = !$show_login_form && !$show_register_form && (empty($show_action_form) || (!empty($action_error) && !in_array($show_action_form, ['delete_confirm', 'edit_confirm', 'edit_fields'])));

if ($fetch_page_data) {
  if ($show_board_index) {
    // --- Board Index View ---
    try {
      $thread_count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
      $reply_count_stmt = $db->prepare("SELECT COUNT(r.id) FROM replies r JOIN threads t ON r.thread_id = t.id WHERE t.channel = ?");
      foreach (ALLOWED_CHANNELS as $channel_code) {
        $display_name = CHANNEL_NAMES[$channel_code] ?? $channel_code;
        $thread_count_stmt->execute([$channel_code]); $thread_count = $thread_count_stmt->fetchColumn();
        $reply_count_stmt->execute([$channel_code]); $reply_count = $reply_count_stmt->fetchColumn();
        $board_index_data[$channel_code] = ['code' => $channel_code, 'name' => $display_name, 'total_posts' => $thread_count + $reply_count];
      }
      // Order by category
      $ordered_board_index_data = [];
      foreach ($channel_categories as $category_name => $category_channels) {
        foreach ($category_channels as $channel_code) {
          if (isset($board_index_data[$channel_code])) {
            $ordered_board_index_data[$channel_code] = $board_index_data[$channel_code];
          }
        }
      }
      foreach (ALLOWED_CHANNELS as $channel_code) { // Add uncategorized
        if (!isset($ordered_board_index_data[$channel_code]) && isset($board_index_data[$channel_code])) {
          $ordered_board_index_data[$channel_code] = $board_index_data[$channel_code];
        }
      }
      $board_index_data = $ordered_board_index_data;
    } catch (PDOException $e) { die("Database Fetch Error (Board Index): " . $e->getMessage()); }
  } else {
    // --- Channel or Thread View ---
    try {
      $user_ids_to_fetch = [];

      if ($viewing_thread_id) {
        // Thread View
        $stmt = $db->prepare("SELECT * FROM threads WHERE id = ? AND channel = ?");
        $stmt->execute([$viewing_thread_id, $current_channel_code]);
        $thread_op = $stmt->fetch();

        if ($thread_op) {
          if ($thread_op['user_id']) $user_ids_to_fetch[] = $thread_op['user_id'];
          $threads = [$thread_op];

          $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id = ? ORDER BY created_at ASC");
          $replies_stmt->execute([$viewing_thread_id]);
          $all_replies = $replies_stmt->fetchAll();
          $replies_to_display[$viewing_thread_id] = $all_replies;
          $reply_counts[$viewing_thread_id] = count($all_replies);
          foreach ($all_replies as $reply) {
            if ($reply['user_id']) $user_ids_to_fetch[] = $reply['user_id'];
          }
        } else {
          $action_error = $action_error ?? ("Thread ID " . htmlspecialchars($viewing_thread_id) . " not found in /" . htmlspecialchars($current_channel_code) . "/.");
          $viewing_thread_id = null; // Force board view
        }
      }

      // Board View
      if (!$viewing_thread_id) {
        $current_page = max(1, filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT) ?: 1);
        $count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
        $count_stmt->execute([$current_channel_code]);
        $total_threads = $count_stmt->fetchColumn();
        $total_pages = max(1, ceil($total_threads / THREADS_PER_PAGE));
        $current_page = min($current_page, $total_pages);
        $offset = ($current_page - 1) * THREADS_PER_PAGE;

        $threads_stmt = $db->prepare("SELECT * FROM threads WHERE channel = ? ORDER BY last_reply_at DESC LIMIT ? OFFSET ?");
        $threads_stmt->bindValue(1, $current_channel_code, PDO::PARAM_STR);
        $threads_stmt->bindValue(2, THREADS_PER_PAGE, PDO::PARAM_INT);
        $threads_stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $threads_stmt->execute();
        $threads = $threads_stmt->fetchAll();
        foreach ($threads as $thread) {
          if ($thread['user_id']) $user_ids_to_fetch[] = $thread['user_id'];
        }

        $threads_on_page_ids = array_column($threads, 'id');
        if (!empty($threads_on_page_ids)) {
          $placeholders = implode(',', array_fill(0, count($threads_on_page_ids), '?'));

          // Fetch counts
          $count_stmt = $db->prepare("SELECT thread_id, COUNT(*) as count FROM replies WHERE thread_id IN ($placeholders) GROUP BY thread_id");
          $count_stmt->execute($threads_on_page_ids);
          $reply_counts_fetched = $count_stmt->fetchAll(PDO::FETCH_KEY_PAIR);
          foreach ($threads_on_page_ids as $tid) { $reply_counts[$tid] = $reply_counts_fetched[$tid] ?? 0; }

          // Fetch replies for preview
          $all_replies_for_page = [];
          $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id IN ($placeholders) ORDER BY created_at ASC");
          $replies_stmt->execute($threads_on_page_ids);
          while ($reply = $replies_stmt->fetch()) {
            $all_replies_for_page[$reply['thread_id']][] = $reply;
            if ($reply['user_id']) $user_ids_to_fetch[] = $reply['user_id'];
          }

          // Slice last N
          foreach ($all_replies_for_page as $tid => $thread_replies) {
            $start_index = max(0, count($thread_replies) - REPLIES_PREVIEW_COUNT);
            $replies_to_display[$tid] = array_slice($thread_replies, $start_index);
          }
          foreach ($threads_on_page_ids as $tid) { // Ensure entry exists
            if (!isset($replies_to_display[$tid])) $replies_to_display[$tid] = [];
          }
        }
      }

      // Fetch User Data
      $unique_user_ids = array_unique(array_filter($user_ids_to_fetch));
      if (!empty($unique_user_ids)) {
        $user_placeholders = implode(',', array_fill(0, count($unique_user_ids), '?'));
        $user_stmt = $db->prepare("SELECT id, username, role, status FROM users WHERE id IN ($user_placeholders)");
        $user_stmt->execute($unique_user_ids);
        while ($user_row = $user_stmt->fetch()) {
          $users_data[$user_row['id']] = $user_row;
        }
      }

    } catch (PDOException $e) {
      error_log("Database Fetch Error (Channel/Thread): " . $e->getMessage());
      die("Database Fetch Error: " . $e->getMessage());
    }
  }
} // end if ($fetch_page_data)

// Get current user *after* potential login/logout actions
$current_user = get_current_user();
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/HDBoard.png">
    <!-- Text Formatter -->
    <title><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code ?? '...') . '/ - ' . htmlspecialchars($current_channel_display_name ?? '...') . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></title>
    <style>
      :root {
        --bg-color: #1a1a1a; --text-color: #e0e0e0; --border-color: #444; --post-bg: #282828;
        --header-bg: #333; --link-color: #7aa2f7; --link-hover: #c0caf5; --accent-red: #f7768e;
        --accent-green: #9ece6a; --accent-blue: #4f6dac; --greentext-color: #9ece6a; --reply-mention-color: #f7768e;
        --form-bg: #303030; --input-bg: #404040; --input-text: #e0e0e0; --input-border: #555;
        --button-bg: #555; --button-hover-bg: #666; --button-text: #e0e0e0; --warning-bg: #5c2424;
        --warning-border: #a04040; --warning-text: #f7768e; --success-bg: #2a502a; --success-border: #4a804a;
        --success-text: #9ece6a; --error-bg: var(--warning-bg); --error-border: var(--warning-border);
        --error-text: var(--warning-text); --code-bg: #222; --code-text: #ccc; --board-index-item-bg: var(--post-bg);
        --board-index-item-border: var(--border-color); --board-index-item-hover-bg: #383838;
        --summary-bg: var(--button-bg); --summary-hover-bg: var(--button-hover-bg);
        --action-form-bg: var(--form-bg);
        --spoiler-bg: #222; --spoiler-text: var(--spoiler-bg); --spoiler-hover-text: var(--text-color);
        --quote-border: #666; --quote-bg: #333; --quote-cite: #aaa;
        --role-user-color: #bbb; --role-janitor-color: #ffcc66; --role-moderator-color: #9ece6a; --role-admin-color: #f7768e;
        --status-banned-color: #f7768e;
      }
      body {
        background-color: var(--bg-color);
        color: var(--text-color);
        font-family: sans-serif;
        font-size: 10pt;
        margin: 0;
        padding: 0;
      }
      .container {
        max-width: 900px;
        margin: 15px auto;
        padding: 0 15px;
      }
      a {
        color: var(--link-color);
        text-decoration: none;
      }
      a:hover {
        color: var(--link-hover);
        text-decoration: underline;
      }
      header {
        background-color: var(--header-bg);
        border: 1px solid var(--border-color);
        border-bottom-width: 2px;
        margin-bottom: 15px;
        padding: 10px;
        position: relative;
      }
      header h1 {
        color: var(--accent-red);
        margin: 5px 0;
        font-size: 1.8em;
        text-align: center;
      }
      .auth-links {
        position: absolute;
        top: 5px;
        right: 10px;
        font-size: 0.9em;
      }
      .auth-links a, .auth-links span {
        margin-left: 10px;
        color: var(--link-color);
      }
      .auth-links a:hover {
        color: var(--link-hover);
      }
      .auth-links form {
        display: inline;
      }
      .auth-links button {
        background: none;
        border: none;
        color: var(--accent-red);
        cursor: pointer;
        padding: 0;
        font-size: inherit;
        text-decoration: underline;
        margin-left: 10px;
      }
      .auth-links button:hover {
        color: var(--link-hover);
      }
      .channel-nav {
        margin-top: 10px;
        padding: 10px 0;
        border-top: 1px dashed var(--border-color);
      }
      .channel-nav-collapsible {
        border: 1px solid var(--border-color);
        border-radius: 4px;
        margin-bottom: 10px;
        background-color: var(--post-bg);
      }
      .channel-nav-collapsible summary {
        padding: 8px 12px;
        cursor: pointer;
        font-weight: bold;
        background-color: var(--summary-bg);
        border-radius: 3px;
        transition: background-color 0.2s ease;
        list-style: none;
        text-align: center;
      }
      .channel-nav-collapsible summary:hover {
        background-color: var(--summary-hover-bg);
      }
      .channel-nav-collapsible summary::-webkit-details-marker {
        display: none;
      }
      .channel-nav-collapsible summary::before {
        content: '► ';
        font-size: 0.8em;
        margin-right: 5px;
      }
      .channel-nav-collapsible[open] summary::before {
        content: '▼ ';
      }
      .channel-nav-content {
        padding: 10px 15px;
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 5px 10px;
      }
      .channel-nav-category {
        width: 100%;
        text-align: center;
        font-weight: bold;
        color: var(--accent-green);
        margin: 10px 0 5px 0;
        font-size: 0.9em;
        border-bottom: 1px dotted var(--border-color);
        padding-bottom: 3px;
      }
      .channel-nav-category:first-of-type {
        margin-top: 0;
      }
      .channel-nav-content a, .board-index-home-link {
        display: inline-block;
        padding: 4px 8px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background-color: var(--input-bg);
        color: var(--link-color);
        font-weight: normal;
        transition: background-color 0.2s ease, border-color 0.2s ease;
        margin-bottom: 5px;
        font-size: 0.95em;
      }
      .channel-nav-content a:hover, .board-index-home-link:hover {
        background-color: var(--button-hover-bg);
        border-color: var(--link-hover);
        color: var(--link-hover);
        text-decoration: none;
      }
      .channel-nav-content a.active {
        background-color: var(--accent-blue);
        color: var(--button-text);
        border-color: var(--link-color);
        font-weight: bold;
      }
      .board-index-home-link.active {
        background-color: var(--accent-red);
        color: var(--button-text);
        border-color: var(--accent-red);
        font-weight: bold;
      }
      .nsfw-warning {
        background-color: var(--warning-bg);
        border: 1px solid var(--warning-border);
        color: var(--warning-text);
        padding: 10px 30px 10px 10px;
        margin-bottom: 15px;
        text-align: center;
        font-weight: bold;
        position: relative;
      }
      .nsfw-warning-close {
        position: absolute;
        top: 5px;
        right: 8px;
        background: none;
        border: none;
        font-size: 1.2em;
        font-weight: bold;
        color: var(--warning-text);
        cursor: pointer;
        padding: 0 5px;
        line-height: 1;
      }
      .nsfw-warning-close:hover {
        color: var(--text-color);
      }
      .post-form, .action-form, .auth-form {
        background-color: var(--form-bg);
        border: 1px solid var(--border-color);
        padding: 15px;
        margin-bottom: 20px;
      }
      .action-form {
        background-color: var(--action-form-bg);
      }
      .post-form h2, .action-form h2, .action-form h3, .auth-form h2 {
        margin: 0 0 10px 0;
        color: var(--accent-blue);
        font-size: 1.2em;
        display: inline-block;
        vertical-align: middle;
      }
      .action-form h3 {
        font-size: 1.1em;
        color: var(--accent-red);
      }
      .post-form .toggle-button {
        padding: 4px 10px;
        font-size: 0.9em;
        cursor: pointer;
        background-color: var(--button-bg);
        color: var(--button-text);
        border: 1px solid var(--input-border);
        border-radius: 3px;
        margin-left: 10px;
        vertical-align: middle;
        transition: background-color 0.2s ease;
      }
      .post-form .toggle-button:hover {
        background-color: var(--button-hover-bg);
      }
      .post-form-content {
        margin-top: 10px;
        padding-top: 10px;
        border-top: 1px dashed var(--border-color);
      }
      .reply-form-container {
        background-color: var(--form-bg);
        border: 1px solid var(--border-color);
        padding: 15px;
        margin-top: 10px;
        margin-bottom: 10px;
      }
      .post-form table, .reply-form-container table, .action-form table, .auth-form table {
        border-collapse: collapse;
        width: 100%;
      }
      .post-form th, .post-form td, .reply-form-container th, .reply-form-container td, .action-form th, .action-form td, .auth-form th, .auth-form td {
        padding: 6px;
        vertical-align: top;
        text-align: left;
      }
      .post-form th, .reply-form-container th, .action-form th, .auth-form th {
        width: 130px;
        text-align: right;
        font-weight: bold;
        color: var(--text-color);
        padding-right: 10px;
      }
      .reply-form-container th, .action-form th {
        width: 110px;
      }
      .auth-form th {
        width: 150px;
      }
      .post-form td, .reply-form-container td, .action-form td, .auth-form td {
        width: auto;
      }
      .post-form input[type="text"], .post-form input[type="password"], .post-form textarea, .post-form select,
      .reply-form-container input[type="text"], .reply-form-container input[type="password"], .reply-form-container textarea,
      .action-form input[type="text"], .action-form input[type="password"], .action-form textarea,
      .auth-form input[type="text"], .auth-form input[type="password"], .auth-form input[type="email"]
      {
        width: calc(100% - 16px);
        padding: 7px;
        border: 1px solid var(--input-border);
        box-sizing: border-box;
        font-size: 1em;
        background-color: var(--input-bg);
        color: var(--input-text);
      }
      .post-form textarea, .reply-form-container textarea, .action-form textarea {
        resize: vertical;
      }
      .post-form input[type="file"], .reply-form-container input[type="file"] {
        padding: 5px 0;
        color: var(--text-color);
      }
      input[type="file"]::file-selector-button {
        background-color: var(--button-bg);
        color: var(--button-text);
        border: 1px solid var(--input-border);
        padding: 4px 8px;
        border-radius: 3px;
        cursor: pointer;
        margin-right: 10px;
      }
      input[type="file"]::file-selector-button:hover {
        background-color: var(--button-hover-bg);
      }
      .post-form input[type="submit"], .reply-form-container input[type="submit"], .action-form input[type="submit"], .auth-form input[type="submit"] {
        padding: 6px 15px;
        font-weight: bold;
        cursor: pointer;
        background-color: var(--button-bg);
        color: var(--button-text);
        border: 1px solid var(--input-border);
        border-radius: 3px;
      }
      .post-form input[type="submit"]:hover, .reply-form-container input[type="submit"]:hover, .action-form input[type="submit"]:hover, .auth-form input[type="submit"]:hover {
        background-color: var(--button-hover-bg);
      }
      .post-form small, .reply-form-container small, .action-form small, .auth-form small {
        color: #aaa;
        font-size: 0.9em;
      }
      hr {
        border: 0;
        border-top: 1px solid var(--border-color);
        margin: 25px 0;
      }
      .board-index-list {
        list-style: none;
        padding: 0;
        margin: 20px 0;
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
        gap: 10px;
      }
      .board-index-list li {
        background-color: var(--board-index-item-bg);
        border: 1px solid var(--board-index-item-border);
        border-radius: 4px;
        transition: background-color 0.2s ease;
      }
      .board-index-list li:hover {
        background-color: var(--board-index-item-hover-bg);
      }
      .board-index-list a {
        display: block;
        padding: 10px 15px;
        color: var(--link-color);
        text-decoration: none;
      }
      .board-index-list a:hover {
        color: var(--link-hover);
        text-decoration: none;
      }
      .board-index-list .board-code {
        font-weight: bold;
        color: var(--accent-green);
        font-size: 1.1em;
      }
      .board-index-list .board-name {
        display: block;
        margin-top: 3px;
        font-size: 0.95em;
        color: var(--text-color);
      }
      .board-index-list .board-post-count {
        display: block;
        font-size: 0.85em;
        color: #aaa;
        margin-top: 5px;
        text-align: right;
      }
      .thread, .reply {
        background-color: var(--post-bg);
        border: 1px solid var(--border-color);
        margin-bottom: 10px;
        padding: 8px 12px;
        word-wrap: break-word;
        overflow-wrap: break-word;
      }
      .reply-container {
        margin-left: 20px;
        margin-top: 10px;
      }
      .reply {
        margin-top: 5px;
        padding: 6px 10px;
        max-width: calc(100% - 20px);
        min-width: 200px;
        box-sizing: border-box;
      }
      .post-info {
        margin-bottom: 3px;
        font-size: 0.95em;
      }
      .post-info .subject {
        color: var(--accent-blue);
        margin-right: 5px;
        font-weight: bold;
      }
      .post-info .name {
        color: var(--accent-green);
        font-weight: bold;
        margin-right: 8px;
      }
      .post-info .role {
        font-size: 0.85em;
        margin-left: 2px;
        font-weight: normal;
        vertical-align: middle;
      }
      .role-user {
        color: var(--role-user-color);
      }
      .role-janitor {
        color: var(--role-janitor-color);
        font-weight: bold;
      }
      .role-moderator {
        color: var(--role-moderator-color);
        font-weight: bold;
      }
      .role-admin {
        color: var(--role-admin-color);
        font-weight: bold;
      }
      .status-banned {
        color: var(--status-banned-color);
        font-style: italic;
        text-decoration: line-through;
        margin-left: 4px;
      }
      .post-info .time, .post-info .post-id {
        font-size: 0.9em;
        color: #bbb;
        font-weight: normal;
        margin-left: 8px;
      }
      .post-info .reply-link, .post-info .action-link {
        font-size: 0.9em;
        color: #bbb;
        text-decoration: none;
        font-weight: normal;
        margin-left: 8px;
      }
      .post-info .reply-link a, .post-info .action-link a {
        color: var(--link-color);
      }
      .post-info .reply-link a:hover, .post-info .action-link a:hover {
        color: var(--link-hover);
      }
      .post-info .action-link a, .post-info .action-link button {
        color: var(--accent-red);
      }
      .post-info .action-link a:hover, .post-info .action-link button:hover {
        color: var(--link-hover);
      }
      .post-info .action-link button {
        background:none;
        border:none;
        padding:0;
        font: inherit;
        cursor: pointer;
        text-decoration: underline;
      }
      .post-info .reply-count {
        font-size: 0.9em;
        color: #bbb;
        font-weight: normal;
        margin-left: 5px;
      }
      .file-info {
        font-size: 0.9em;
        color: #ccc;
        margin-bottom: 8px;
        display: flex;
        align-items: flex-start;
        flex-wrap: wrap;
        gap: 5px 10px;
        border-bottom: 1px dashed var(--border-color);
        padding-bottom: 5px;
        margin-top: 5px;
      }
      .file-info:last-of-type {
        border-bottom: none;
        margin-bottom: 10px;
      }
      .file-info .media-toggle {
        flex-shrink: 0;
      }
      .file-info .media-toggle button.show-media-btn {
        padding: 4px 8px;
        cursor: pointer;
        font-size: 0.9em;
        background-color: var(--button-bg);
        border: 1px solid var(--input-border);
        border-radius: 3px;
        color: var(--button-text);
        line-height: 1.2;
        text-transform: none;
        white-space: normal;
        text-align: center;
      }
      .file-info .media-toggle button.show-media-btn:hover {
        background-color: var(--button-hover-bg);
      }
      .file-details {
        flex-grow: 1;
        line-height: 1.4;
        word-break: break-all;
      }
      .file-details a {
        color: var(--link-color);
        text-decoration: underline;
      }
      .file-details a:hover {
        color: var(--link-hover);
      }
      .media-container {
        margin-top: 8px;
        margin-bottom: 10px;
        border: 1px dashed var(--border-color);
        padding: 5px;
        display: none;
        max-width: 100%;
        box-sizing: border-box;
        overflow: hidden;
        background-color: var(--bg-color);
      }
      .media-container img, .media-container video, .media-container iframe {
        display: block;
        max-width: 100%;
        height: auto;
        margin: 0 auto;
        background-color: #000;
      }
      .media-container audio {
        display: block;
        width: 100%;
        min-height: 30px;
        height: auto;
        margin: 0 auto;
      }
      .youtube-embed-container, .video-embed-container {
        margin: 5px 0;
        position: relative;
        padding-bottom: 56.25%;
        height: 0;
        overflow: hidden;
        max-width: 100%;
        background: #000;
      }
      .youtube-embed-container iframe, .video-embed-container video {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        border: none;
      }
      .comment {
        margin-top: 10px;
        line-height: 1.5;
        overflow-wrap: break-word;
        word-break: break-word;
        color: var(--text-color);
      }
      .comment-truncated {
        display: block;
      }
      .comment-full {
        display: none;
      }
      .show-full-text-btn {
        display: inline-block;
        padding: 2px 5px;
        font-size: 0.8em;
        cursor: pointer;
        margin-left: 5px;
        margin-top: 5px;
        background-color: var(--button-bg);
        border: 1px solid var(--input-border);
        border-radius: 3px;
        color: var(--button-text);
      }
      .show-full-text-btn:hover {
        background-color: var(--button-hover-bg);
      }
      .greentext {
        color: var(--greentext-color);
      }
      .reply-mention {
        color: var(--reply-mention-color);
        text-decoration: none;
        font-weight: bold;
      }
      .reply-mention:hover {
        color: var(--link-hover);
        text-decoration: underline;
      }
      .omitted-posts {
        font-size: 0.9em;
        color: #aaa;
        margin-left: 20px;
        margin-top: 5px;
        margin-bottom: 10px;
      }
      .omitted-posts a {
        color: var(--link-color);
        text-decoration: none;
      }
      .omitted-posts a:hover {
        text-decoration: underline;
      }
      .error, .success {
        font-weight: bold;
        border: 1px solid;
        padding: 10px;
        margin-bottom: 15px;
        border-radius: 4px;
        text-align: center;
      }
      .error {
        color: var(--error-text);
        background-color: var(--error-bg);
        border-color: var(--error-border);
      }
      .success {
        color: var(--success-text);
        background-color: var(--success-bg);
        border-color: var(--success-border);
      }
      .pagination {
        text-align: center;
        margin: 20px 0;
        font-size: 1.1em;
      }
      .pagination a, .pagination span {
        display: inline-block;
        padding: 5px 10px;
        margin: 0 3px;
        border: 1px solid var(--border-color);
        background-color: var(--post-bg);
        text-decoration: none;
        color: var(--link-color);
        border-radius: 3px;
      }
      .pagination a:hover {
        background-color: var(--button-hover-bg);
        border-color: var(--link-hover);
      }
      .pagination span.current-page {
        background-color: var(--accent-red);
        color: var(--button-text);
        font-weight: bold;
        border-color: var(--accent-red);
      }
      .pagination span.disabled {
        color: #888;
        cursor: not-allowed;
        background-color: var(--header-bg);
        border-color: var(--border-color);
      }
      .thread-view-header {
        background-color: var(--header-bg);
        border: 1px solid var(--border-color);
        margin-bottom: 15px;
        padding: 10px;
        text-align: center;
        font-size: 1.1em;
        font-weight: bold;
        color: var(--text-color);
      }
      .thread-view-header a {
        color: var(--accent-red);
      }
      .thread-view-header a:hover {
        color: var(--link-hover);
      }
      :target {
        scroll-margin-top: 70px;
      }
      .post.highlighted, .reply.highlighted {
        background-color: #404050 !important;
        border-color: var(--link-color) !important;
        transition: background-color 0.3s ease, border-color 0.3s ease;
      }
      #post-form h4, .reply-form-container h4 {
        margin: 0 0 10px 0;
        color: var(--accent-blue);
      }
      .action-form .post-preview {
        background-color: var(--post-bg);
        border: 1px dashed var(--border-color);
        padding: 10px;
        margin-bottom: 15px;
        font-size: 0.9em;
        max-height: 100px;
        overflow: auto;
      }
      .flex-container {
        display: flex;
        justify-content: center;
      }
      .flex-container img {
        max-width: 100%;
        height: auto;
        max-height: 250px;
        margin: 10px auto;
        display: block;
      }
      .spoiler {
        background-color: var(--spoiler-bg);
        color: var(--spoiler-text);
        padding: 0 3px;
        border-radius: 2px;
        cursor: help;
        transition: color 0.2s ease;
      }
      .spoiler:hover {
        color: var(--spoiler-hover-text);
      }
      pre.code-block {
        background-color: var(--code-bg);
        border: 1px solid var(--border-color);
        padding: 10px;
        margin: 10px 0;
        overflow-x: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        font-family: monospace;
        font-size: 0.95em;
        color: var(--code-text);
      }
      pre.code-block code {
        font-family: inherit;
        white-space: inherit;
      }
      blockquote.quote-block {
        border-left: 3px solid var(--quote-border);
        background-color: var(--quote-bg);
        padding: 8px 12px;
        margin: 10px 0 10px 15px;
        color: var(--text-color);
      }
      blockquote.quote-block cite {
        display: block;
        font-style: italic;
        color: var(--quote-cite);
        margin-bottom: 5px;
        font-size: 0.9em;
      }
      /* --- Text Formatter Toolbar --- */
      .text-formatter-toolbar {
        margin-bottom: 5px;
        padding: 3px;
        background-color: var(--input-bg);
        border: 1px solid var(--input-border);
        border-bottom: none; /* Attach to top of textarea */
        border-radius: 3px 3px 0 0;
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
      }
      .text-formatter-toolbar button.format-button {
        background-color: var(--button-bg);
        color: var(--button-text);
        border: 1px solid var(--input-border);
        padding: 3px 7px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 0.9em;
        font-family: sans-serif; /* Ensure consistent font */
        line-height: 1.2;
        min-width: 25px; /* Ensure buttons have some width */
        text-align: center;
      }
      .text-formatter-toolbar button.format-button:hover {
        background-color: var(--button-hover-bg);
      }
      /* Adjust textarea border radius when toolbar is present */
      .text-formatter-toolbar + textarea {
        border-top-left-radius: 0;
        border-top-right-radius: 0;
        border-top: 1px solid var(--input-border); /* Ensure top border is visible */
      }
      @media (max-width: 767px) {
        body {
          font-size: 11pt;
        }
        .container {
          padding: 0 10px;
        }
        header h1 {
          font-size: 1.5em;
        }
        .auth-links {
          position: static;
          text-align: center;
          margin-top: 5px;
        }
        .channel-nav-content {
          font-size: 0.9em;
          gap: 4px 8px;
        }
        .board-index-list {
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        }
        .post-form th, .reply-form-container th, .action-form th, .auth-form th {
          width: auto;
          text-align: left;
          display: block;
          padding-bottom: 2px;
          padding-right: 6px;
        }
        .post-form td, .reply-form-container td, .action-form td, .auth-form td {
          display: block;
          padding-top: 0;
        }
        .post-form input[type="text"], .post-form input[type="password"], .post-form textarea, .post-form select,
        .reply-form-container input[type="text"], .reply-form-container input[type="password"], .reply-form-container textarea,
        .action-form input[type="text"], .action-form input[type="password"], .action-form textarea,
        .auth-form input[type="text"], .auth-form input[type="password"] {
          width: calc(100% - 12px);
          padding: 6px;
        }
        .post-form input[type="submit"], .reply-form-container input[type="submit"], .action-form input[type="submit"], .auth-form input[type="submit"] {
          display: block;
          width: auto;
          margin-top: 10px;
        }
        .file-info {
          flex-direction: column;
          align-items: stretch;
          gap: 5px 0;
        }
        .file-info .media-toggle {
          margin-bottom: 5px;
        }
        .file-info .file-details {
          margin-top: 0;
          font-size: 1em;
        }
        .reply-container {
          margin-left: 0;
        }
        .reply, .omitted-posts, .reply-form-container {
          margin-left: 5px;
          margin-right: 5px;
          max-width: calc(100% - 10px);
          min-width: auto;
        }
        .post-info {
          font-size: 0.9em;
        }
        .post-info .name {
          display: block;
          margin-bottom: 3px;
        }
        .post-info .time, .post-info .post-id, .post-info .reply-link, .post-info .action-link, .post-info .reply-count {
          font-size: 0.95em;
          margin-left: 4px;
          display: inline-block;
          margin-bottom: 3px;
          margin-right: 5px;
        }
        .post-info .time:first-of-type {
          margin-left: 0;
        }
        .pagination {
          font-size: 1em;
        }
        .pagination a, .pagination span {
          padding: 3px 6px;
        }
        .thread-view-header {
          font-size: 1em;
        }
        :target {
          scroll-margin-top: 60px;
        }
      }
      @media (min-width: 768px) {
        .auth-links {
          position: absolute;
          top: 5px;
          right: 10px;
        }
        .post-form th, .action-form th, .auth-form th {
          width: 130px;
          text-align: right;
          display: table-cell;
        }
        .post-form td, .action-form td, .auth-form td {
          display: table-cell;
        }
        .reply-form-container th {
          width: 110px;
        }
        .auth-form th {
          width: 150px;
        }
        .file-info {
          flex-direction: row;
          align-items: flex-start;
          gap: 5px 10px;
        }
        .file-info .media-toggle {
          margin-bottom: 0;
        }
        .file-info .file-details {
          margin-top: 0;
        }
        .reply-container {
          margin-left: 20px;
        }
        .reply, .omitted-posts, .reply-form-container {
          margin-left: 20px;
          margin-right: 0;
          max-width: calc(100% - 20px);
        }
        .post-info .name {
          display: inline-block;
          margin-bottom: 0;
        }
        .post-info .time, .post-info .post-id, .post-info .reply-link, .post-info .action-link, .post-info .reply-count {
          font-size: 0.9em;
          margin-left: 8px;
          display: inline;
          margin-bottom: 0;
          margin-right: 0;
        }
      }
    </style>
    <script>
      <?php if (!$show_board_index && $current_channel_code) : ?>
        const currentChannel = "<?php echo htmlspecialchars($current_channel_code); ?>";
      <?php else : ?>
        const currentChannel = null;
      <?php endif; ?>
      const isLoggedIn = <?php echo json_encode(is_logged_in()); ?>;
      const currentUser = <?php echo json_encode($current_user); ?>;
    </script>
    <script>
      /**
       * Inserts BBCode tags around selected text or at the cursor position.
       * @param {string} textareaId The ID of the target textarea.
       * @param {string} tag The BBCode tag name (e.g., 'b', 'i', 'spoiler').
       */
      function insertBbCode(textareaId, tag) {
        const textarea = document.getElementById(textareaId);
        if (!textarea) return;

        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const selectedText = textarea.value.substring(start, end);
        const textBefore = textarea.value.substring(0, start);
        const textAfter = textarea.value.substring(end);

        let replacement = '';
        let cursorPosition = start;

        if (selectedText) {
          // Wrap selected text
          replacement = `[${tag}]${selectedText}[/${tag}]`;
          cursorPosition = start + replacement.length;
        } else {
          // Insert tags at cursor position
          replacement = `[${tag}][/${tag}]`;
          // Place cursor between the tags
          cursorPosition = start + `[${tag}]`.length;
        }

        textarea.value = textBefore + replacement + textAfter;

        // Set focus and cursor position
        textarea.focus();
        textarea.selectionStart = textarea.selectionEnd = cursorPosition;
      }

      const IMAGE_TYPES = ['image'];
      const VIDEO_TYPES = ['video'];
      const AUDIO_TYPES = ['audio'];
      const YOUTUBE_TYPE = 'youtube';

      function toggleMedia(button) {
        const fileInfoDiv = button.closest('.file-info');
        if (!fileInfoDiv) return;
        const mediaContainer = fileInfoDiv.nextElementSibling;
        if (!mediaContainer || !mediaContainer.classList.contains('media-container')) return;
        const mediaId = button.dataset.mediaId;
        const mediaUrl = button.dataset.mediaUrl;
        const mediaType = button.dataset.mediaType;
        if (!mediaId || !mediaUrl || !mediaType) return;

        const isHidden = (mediaContainer.style.display === 'none' || mediaContainer.style.display === '');
        let viewButtonText = 'View Media';
        let hideButtonText = 'Hide Media';

        if (IMAGE_TYPES.includes(mediaType)) { viewButtonText = 'View Image'; hideButtonText = 'Hide Image'; }
        else if (VIDEO_TYPES.includes(mediaType)) { viewButtonText = 'View Video'; hideButtonText = 'Hide Video'; }
        else if (AUDIO_TYPES.includes(mediaType)) { viewButtonText = 'View Audio'; hideButtonText = 'Hide Audio'; }
        else if (mediaType === YOUTUBE_TYPE) { viewButtonText = 'View YouTube'; hideButtonText = 'Hide YouTube'; }

        if (isHidden) {
          mediaContainer.style.display = 'block';
          button.textContent = hideButtonText;
          const loadedUrl = mediaContainer.dataset.loadedUrl;
          const mediaElementExists = mediaContainer.querySelector('video, audio, iframe, img');
          const needsLoad = !loadedUrl || loadedUrl !== mediaUrl || !mediaElementExists;

          if (needsLoad) {
            mediaContainer.innerHTML = '<span>Loading...</span>';
            mediaContainer.dataset.loadedUrl = mediaUrl;
            let mediaElement = null;

            if (IMAGE_TYPES.includes(mediaType)) {
              mediaElement = document.createElement('img');
              mediaElement.src = mediaUrl;
              mediaElement.alt = 'Media Image';
              mediaElement.loading = 'lazy';
              const linkElement = document.createElement('a');
              linkElement.href = mediaUrl;
              linkElement.target = '_blank';
              linkElement.rel = 'noopener noreferrer';
              linkElement.appendChild(mediaElement);
              mediaContainer.innerHTML = '';
              mediaContainer.appendChild(linkElement);
            } else if (VIDEO_TYPES.includes(mediaType)) {
              mediaElement = document.createElement('video');
              mediaElement.src = mediaUrl;
              mediaElement.controls = true;
              mediaElement.playsinline = true;
              mediaElement.preload = 'metadata';
              const embedContainer = document.createElement('div');
              embedContainer.classList.add('video-embed-container');
              embedContainer.appendChild(mediaElement);
              mediaContainer.innerHTML = '';
              mediaContainer.appendChild(embedContainer);
            } else if (AUDIO_TYPES.includes(mediaType)) {
              mediaElement = document.createElement('audio');
              mediaElement.src = mediaUrl;
              mediaElement.controls = true;
              mediaElement.preload = 'metadata';
              mediaContainer.innerHTML = '';
              mediaContainer.appendChild(mediaElement);
            } else if (mediaType === YOUTUBE_TYPE) {
              const youtubeRegexMatch = mediaUrl.match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|m\.youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/);
              const videoId = (youtubeRegexMatch && youtubeRegexMatch[1]) ? youtubeRegexMatch[1] : null;
              if (videoId) {
                const embedUrl = `https://www.youtube.com/embed/${videoId}`;
                mediaElement = document.createElement('iframe');
                mediaElement.src = embedUrl;
                mediaElement.setAttribute('frameborder', '0');
                mediaElement.setAttribute('allow', 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share');
                mediaElement.setAttribute('allowfullscreen', '');
                mediaElement.loading = 'lazy';
                const embedContainer = document.createElement('div');
                embedContainer.classList.add('youtube-embed-container');
                embedContainer.appendChild(mediaElement);
                mediaContainer.innerHTML = '';
                mediaContainer.appendChild(embedContainer);
              } else {
                mediaContainer.innerHTML = '<span class="error">Failed to embed YouTube video (Invalid URL).</span>';
              }
            } else {
              mediaContainer.innerHTML = '<span class="error">Unsupported media type: ' + mediaType + '</span>';
            }

            if (mediaElement && (mediaElement.tagName === 'VIDEO' || mediaElement.tagName === 'AUDIO' || mediaElement.tagName === 'IMG' || mediaElement.tagName === 'IFRAME')) {
              mediaElement.onerror = function(e) {
                console.error('Media loading failed:', this.src || this.dataset.mediaUrl, e);
                if (!mediaContainer.querySelector('.media-error-message')) {
                  const errorSpan = document.createElement('span');
                  errorSpan.classList.add('error', 'media-error-message');
                  errorSpan.textContent = 'Failed to load media.';
                  mediaContainer.innerHTML = '';
                  mediaContainer.appendChild(errorSpan);
                }
              };
            }
          }
        } else {
          mediaContainer.style.display = 'none';
          button.textContent = viewButtonText;
          // Pause and clear src for video/audio/iframe to stop playback/loading
          mediaContainer.querySelectorAll('video, audio, iframe').forEach(mediaElement => {
            if ((mediaElement.tagName === 'VIDEO' || mediaElement.tagName === 'AUDIO') && typeof mediaElement.pause === 'function') {
              mediaElement.pause();
              mediaElement.src = ''; // Clear source to potentially stop buffering
            } else if (mediaElement.tagName === 'IFRAME') {
              mediaElement.src = 'about:blank'; // Clear iframe content
            }
          });
          mediaContainer.innerHTML = ''; // Clear container to ensure it's reloaded next time
          delete mediaContainer.dataset.loadedUrl; // Reset loaded state
        }
      }

      function toggleFullText(button, fullTextId) {
        const truncatedDiv = button.closest('.comment-truncated');
        const fullDiv = document.getElementById(fullTextId);
        if (truncatedDiv && fullDiv) {
          truncatedDiv.style.display = 'none';
          fullDiv.style.display = 'block';
        }
      }

      function toggleReplyForm(threadId) {
        var form = document.getElementById('reply-form-' + threadId);
        if (form) {
          var isHidden = (form.style.display === 'none' || form.style.display === '');
          form.style.display = isHidden ? 'block' : 'none';
          if (isHidden) {
            form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            const textarea = form.querySelector('textarea[name="comment"]');
            if (textarea) textarea.focus();
          }
        } else {
          console.warn('Reply form container not found for thread ID:', threadId);
        }
      }

      document.addEventListener('DOMContentLoaded', function() {
        // Event delegation for dynamically added content
        document.body.addEventListener('click', function(event) {
          // Handle media toggle buttons
          if (event.target.matches('.show-media-btn')) {
            toggleMedia(event.target);
          }
          // Handle "View Full Text" buttons
          else if (event.target.matches('.show-full-text-btn')) {
            const fullTextId = event.target.dataset.targetId;
            if (fullTextId) {
              toggleFullText(event.target, fullTextId);
            }
          }
          // Handle NSFW warning close button
          else if (event.target.matches('#nsfw-warning-close')) {
            const nsfwWarning = document.getElementById('nsfw-warning');
            if (nsfwWarning) {
              nsfwWarning.style.display = 'none';
            }
          }
          // Handle quick reply links
          else if (event.target.matches('.reply-link a[href^="#reply-form-"]')) {
            event.preventDefault(); // Prevent default anchor jump
            const hrefAttr = event.target.getAttribute('href');
            if (hrefAttr) {
              const threadIdMatch = hrefAttr.match(/#reply-form-(\d+)/);
              if (threadIdMatch && threadIdMatch[1]) {
                toggleReplyForm(threadIdMatch[1]);
              }
            }
          }
          // Handle post form toggle button
          else if (event.target.matches('#togglePostFormButton')) {
            togglePostForm();
          }
        });

        // Reply mention highlighting
        let highlightTimeout = null;
        function highlightPost(targetPost, addClass) {
          if (!targetPost) return;
          clearTimeout(highlightTimeout);
          if (addClass) {
            targetPost.classList.add('highlighted');
            highlightTimeout = setTimeout(() => targetPost.classList.remove('highlighted'), 1500); // Highlight for 1.5s on hover
          } else {
            targetPost.classList.remove('highlighted');
          }
        }
        document.body.addEventListener('mouseover', function(event) {
          const link = event.target.closest('.reply-mention');
          if (link?.getAttribute('href')?.startsWith('#post-')) {
            const targetId = link.getAttribute('href').substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            highlightPost(targetPost, true);
          }
        });
        document.body.addEventListener('mouseout', function(event) {
          const link = event.target.closest('.reply-mention');
          if (link?.getAttribute('href')?.startsWith('#post-')) {
            const targetId = link.getAttribute('href').substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            highlightPost(targetPost, false);
          }
        });
        // Highlight on click too, maybe slightly longer
        document.body.addEventListener('click', function(event) {
          const link = event.target.closest('.reply-mention');
          if (link?.getAttribute('href')?.startsWith('#post-')) {
            const targetId = link.getAttribute('href').substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            if (targetPost) {
              clearTimeout(highlightTimeout); // Clear any hover highlight timeout
              targetPost.classList.add('highlighted');
              highlightTimeout = setTimeout(() => targetPost.classList.remove('highlighted'), 2500); // Keep highlight for 2.5s on click
            }
          }
        });
        // Highlight post if linked directly via URL hash
        if (window.location.hash?.startsWith('#post-')) {
          const targetId = window.location.hash.substring(1);
          // Use requestAnimationFrame to ensure the element is painted before highlighting
          requestAnimationFrame(() => {
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            if (targetPost) {
              highlightPost(targetPost, true); // Use the same function, maybe adjust timeout if needed here
            }
          });
        }

        // Post form toggle persistence
        const postFormContent = document.getElementById('postFormContent');
        const toggleButton = document.getElementById('togglePostFormButton');
        if (toggleButton) {
          window.togglePostForm = function() { // Make it global for inline onclick compatibility if needed, or keep event listener
            if (!postFormContent) return;
            const isCollapsed = postFormContent.style.display === 'none' || postFormContent.style.display === '';
            const newState = isCollapsed ? 'expanded' : 'collapsed';
            if (newState === 'expanded') {
              postFormContent.style.display = 'block';
              toggleButton.textContent = 'Hide Form';
            } else {
              postFormContent.style.display = 'none';
              toggleButton.textContent = 'Show Form';
            }
            // Save state to localStorage only if on a specific channel page
            if (typeof currentChannel === 'string' && currentChannel) {
              const stateKey = 'postFormState_channel_' + currentChannel;
              try {
                localStorage.setItem(stateKey, newState);
              } catch (e) {
                console.error("LocalStorage error:", e);
              }
            }
          };
          // Initialize form state based on localStorage for the current channel
          if (typeof currentChannel === 'string' && currentChannel && postFormContent) {
            const stateKey = 'postFormState_channel_' + currentChannel;
            let savedState = 'collapsed'; // Default to collapsed
            try {
              savedState = localStorage.getItem(stateKey) || 'collapsed';
            } catch (e) {
              console.error("LocalStorage error:", e);
            }
            if (savedState === 'expanded') {
              postFormContent.style.display = 'block';
              toggleButton.textContent = 'Hide Form';
            } else {
              postFormContent.style.display = 'none';
              toggleButton.textContent = 'Show Form';
            }
          } else if (postFormContent) {
            // Default state if not on a channel or no localStorage support
            postFormContent.style.display = 'none';
            toggleButton.textContent = 'Show Form';
          }
        }
      });
    </script>
  </head>
  <body>
    <div class="container">
      <header>
        <h1><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code ?? '...') . '/ - ' . htmlspecialchars($current_channel_display_name ?? '...') . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></h1>
        <div class="flex-container">
          <img src="/HDBoard.png" alt="HDBoard Logo">
        </div>
        <div class="auth-links">
          <?php if ($current_user): ?>
            <span>Welcome, <strong class="role-<?php echo htmlspecialchars($current_user['role']); ?>"><?php echo htmlspecialchars($current_user['username']); ?></strong>!</span>
            <form action="./" method="post" style="display: inline;">
              <input type="hidden" name="action" value="logout">
              <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
              <button type="submit">Logout</button>
            </form>
          <?php else: ?>
            <a href="./?action=login">Login</a>
            <a href="./?action=register">Register</a>
          <?php endif; ?>
        </div>
        <nav class="channel-nav">
          <?php if (!$show_board_index && $current_channel_code) : ?>
            <details class="channel-nav-collapsible">
              <summary>Show/Hide Board List</summary>
              <div class="channel-nav-content">
          <?php else : ?>
            <div class="channel-nav-content" style="padding-top: 10px; border-top: 1px dashed var(--border-color);">
          <?php endif; ?>
            <?php
              $home_class = $show_board_index ? 'active' : '';
              echo '<a href="./" class="board-index-home-link ' . $home_class . '">Home</a>';
            ?>
            <?php foreach ($channel_categories as $category_name => $category_channels) : ?>
              <span class="channel-nav-category"><?php echo htmlspecialchars($category_name); ?></span>
              <?php foreach ($category_channels as $channel_code_nav) : ?>
                <?php if (isset(CHANNEL_NAMES[$channel_code_nav])) : ?>
                  <?php
                    $display_name = CHANNEL_NAMES[$channel_code_nav];
                    $class = (!$show_board_index && isset($current_channel_code) && $channel_code_nav === $current_channel_code) ? 'active' : '';
                  ?>
                  <a href="./?channel=<?php echo urlencode($channel_code_nav); ?>" class="<?php echo $class; ?>"><?php echo htmlspecialchars($display_name); ?></a>
                <?php endif; ?>
              <?php endforeach; ?>
            <?php endforeach; ?>
            <?php
              // Get uncategorized channels
              $categorized_channels_flat = [];
              if (!empty($channel_categories)) {
                $categorized_channels_flat = array_merge(...array_values($channel_categories));
              }
              $uncategorized = array_diff(ALLOWED_CHANNELS, $categorized_channels_flat);
            ?>
            <?php if (!empty($uncategorized)) : ?>
              <span class="channel-nav-category">Uncategorized</span>
              <?php foreach ($uncategorized as $channel_code_nav) : ?>
                <?php if (isset(CHANNEL_NAMES[$channel_code_nav])) : ?>
                  <?php
                    $display_name = CHANNEL_NAMES[$channel_code_nav];
                    $class = (!$show_board_index && isset($current_channel_code) && $channel_code_nav === $current_channel_code) ? 'active' : '';
                  ?>
                  <a href="./?channel=<?php echo urlencode($channel_code_nav); ?>" class="<?php echo $class; ?>"><?php echo htmlspecialchars($display_name); ?></a>
                <?php endif; ?>
              <?php endforeach; ?>
            <?php endif; ?>
          </div>
          <?php if (!$show_board_index && $current_channel_code) : ?>
            </details>
          <?php endif; ?>
        </nav>
      </header>

      <?php // --- Display Global Messages --- ?>
      <?php if ($post_error): ?><p class="error"><?php echo htmlspecialchars($post_error); ?></p><?php endif; ?>
      <?php if ($post_success): ?><p class="success"><?php echo htmlspecialchars($post_success); ?></p><?php endif; ?>
      <?php if ($action_error): ?><p class="error"><?php echo htmlspecialchars($action_error); ?></p><?php endif; ?>
      <?php if ($action_success): ?><p class="success"><?php echo htmlspecialchars($action_success); ?></p><?php endif; ?>
      <?php if ($auth_error): ?><p class="error"><?php echo htmlspecialchars($auth_error); ?></p><?php endif; ?>
      <?php if ($auth_success): ?><p class="success"><?php echo htmlspecialchars($auth_success); ?></p><?php endif; ?>
      <?php if (isset($_GET['loggedout'])): ?><p class="success">You have been logged out.</p><?php endif; ?>
      <?php if (isset($_GET['user_banned'])): ?><p class="success">User has been banned.</p><?php endif; ?>
      <?php if (isset($_GET['user_unbanned'])): ?><p class="success">User has been unbanned.</p><?php endif; ?>
      <?php if (isset($_GET['deleted'])): ?><p class="success">Post No.<?php echo htmlspecialchars($_GET['deleted']); ?> deleted.</p><?php endif; ?>
      <?php if (isset($_GET['edited'])): ?><p class="success">Post No.<?php echo htmlspecialchars($_GET['edited']); ?> edited.</p><?php endif; ?>

      <?php // --- Display Auth Forms --- ?>
      <?php if ($show_login_form): ?>
        <div class="auth-form">
          <h2>Login</h2>
          <form action="./" method="post">
            <input type="hidden" name="action" value="dologin">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <table>
              <tr><th><label for="username">Username</label></th><td><input type="text" name="username" id="username" required></td></tr>
              <tr><th><label for="password">Password</label></th><td><input type="password" name="password" id="password" required></td></tr>
              <tr><th></th><td><input type="submit" value="Login"></td></tr>
            </table>
          </form>
          <p><small>Don't have an account? <a href="./?action=register">Register here</a>.</small></p>
        </div>
        <hr>
      <?php endif; ?>

      <?php if ($show_register_form): ?>
        <div class="auth-form">
          <h2>Register</h2>
          <form action="./" method="post">
            <input type="hidden" name="action" value="doregister">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <table>
              <tr><th><label for="reg_username">Username</label></th><td><input type="text" name="username" id="reg_username" required maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Letters, numbers, _)</small></td></tr>
              <tr><th><label for="reg_password">Password</label></th><td><input type="password" name="password" id="reg_password" required minlength="<?php echo PASSWORD_MIN_LENGTH; ?>"> <small>(Min <?php echo PASSWORD_MIN_LENGTH; ?> chars)</small></td></tr>
              <tr><th><label for="reg_password_confirm">Confirm Password</label></th><td><input type="password" name="password_confirm" id="reg_password_confirm" required></td></tr>
              <tr><th></th><td><input type="submit" value="Register"></td></tr>
            </table>
          </form>
          <p><small>Already have an account? <a href="./?action=login">Login here</a>.</small></p>
        </div>
        <hr>
      <?php endif; ?>

      <?php // --- Display Action Forms --- ?>
      <?php if ($show_action_form && $post_data_for_form): ?>
        <?php
          $form_post_type = $post_data_for_form['type'] ?? null;
          $form_post_id = $post_data_for_form['id'] ?? null;
          $form_user_info = isset($post_data_for_form['user_id']) && isset($users_data[$post_data_for_form['user_id']]) ? $users_data[$post_data_for_form['user_id']] : null;
          $form_username = $form_user_info ? $form_user_info['username'] : ($post_data_for_form['username'] ?? 'Anonymous');
          $form_comment_preview = isset($post_data_for_form['comment']) ? htmlspecialchars(mb_substr($post_data_for_form['comment'], 0, 100)) . (mb_strlen($post_data_for_form['comment']) > 100 ? '...' : '') : '[No Comment]';
          $form_require_password = $post_data_for_form['require_password'] ?? false;
        ?>
        <?php if ($form_post_type && $form_post_id): ?>
          <div class="action-form">
            <?php if ($show_action_form === 'delete_confirm'): ?>
              <h3>Confirm Deletion</h3>
              <?php if ($form_require_password): ?>
                <p>Please enter the password for legacy user '<strong><?php echo htmlspecialchars($form_username); ?></strong>' to delete this <?php echo htmlspecialchars($form_post_type); ?> (ID: <?php echo $form_post_id; ?>).</p>
              <?php else: ?>
                <p>Are you sure you want to delete this <?php echo htmlspecialchars($form_post_type); ?> (ID: <?php echo $form_post_id; ?>)? Posted by: <strong><?php echo htmlspecialchars($form_username); ?></strong></p>
              <?php endif; ?>
              <div class="post-preview"><strong>Comment starts:</strong> <?php echo $form_comment_preview; ?></div>
              <form action="./" method="post">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <?php if ($form_require_password): ?>
                  <tr><th><label for="password_del">Password</label></th><td><input type="password" name="password" id="password_del" required></td></tr>
                  <?php endif; ?>
                  <tr><th></th><td><input type="submit" value="Confirm Delete <?php echo ucfirst(htmlspecialchars($form_post_type)); ?>"></td></tr>
                </table>
              </form>
            <?php elseif ($show_action_form === 'edit_confirm'): // Only for legacy edits ?>
              <h3>Verify Ownership to Edit Legacy Post</h3>
              <p>Please enter the password for legacy user '<strong><?php echo htmlspecialchars($form_username); ?></strong>' to edit this <?php echo htmlspecialchars($form_post_type); ?> (ID: <?php echo $form_post_id; ?>).</p>
              <div class="post-preview"><strong>Comment starts:</strong> <?php echo $form_comment_preview; ?></div>
              <form action="./" method="post">
                <input type="hidden" name="action" value="edit"> <?php // This POST triggers password check ?>
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <tr><th><label for="password_edit_ver">Password</label></th><td><input type="password" name="password" id="password_edit_ver" required></td></tr>
                  <tr><th></th><td><input type="submit" value="Verify and Edit"></td></tr>
                </table>
              </form>
            <?php elseif ($show_action_form === 'edit_fields'): ?>
              <h3>Edit <?php echo ucfirst(htmlspecialchars($form_post_type)); ?></h3>
              <p>Editing <?php echo htmlspecialchars($form_post_type); ?> ID: <?php echo $form_post_id; ?></p>
              <form action="./" method="post">
                <input type="hidden" name="action" value="save_edit">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <?php if ($form_post_type === 'thread'): ?>
                  <tr><th><label for="subject_edit">Subject</label></th><td><input type="text" name="subject" id="subject_edit" value="<?php echo htmlspecialchars($post_data_for_form['subject_attempt'] ?? $post_data_for_form['subject'] ?? ''); ?>" size="30"></td></tr>
                  <?php endif; ?>
                  <tr><th><label for="comment_edit">Comment</label></th><td><textarea name="comment" id="comment_edit" rows="5" cols="50" required><?php echo htmlspecialchars($post_data_for_form['comment_attempt'] ?? $post_data_for_form['comment'] ?? ''); ?></textarea></td></tr>
                  <tr><th></th><td><input type="submit" value="Save Changes"></td></tr>
                </table>
              </form>
            <?php endif; ?>
          </div>
          <hr>
        <?php else: ?>
          <p class="error">Could not display action form due to missing data.</p>
        <?php endif; ?>
      <?php endif; ?>

      <?php // --- Main Content Display --- ?>
      <?php if ($fetch_page_data): ?>
        <?php if ($show_board_index): // --- Board Index View --- ?>
          <h2>Available Boards</h2>
          <ul class="board-index-list">
            <?php foreach ($board_index_data as $board): ?>
            <li>
              <a href="./?channel=<?php echo urlencode($board['code']); ?>">
                <span class="board-code">/<?php echo htmlspecialchars($board['code']); ?>/</span>
                <span class="board-name"><?php echo htmlspecialchars($board['name']); ?></span>
                <span class="board-post-count">(<?php echo number_format($board['total_posts']); ?> posts)</span>
              </a>
            </li>
            <?php endforeach; ?>
            <?php if (empty($board_index_data)): ?>
              <p style="grid-column: 1 / -1; text-align: center; color: #aaa;">No boards found.</p>
            <?php endif; ?>
          </ul>
          <hr>
          <p style="text-align: center; color: #aaa;">Select a board.</p>

        <?php elseif ($current_channel_code): // --- Channel or Thread View --- ?>
          <?php if (!$viewing_thread_id && in_array($current_channel_code, NSFW_CHANNELS)) : ?>
            <div class="nsfw-warning" id="nsfw-warning">
              <strong>Warning:</strong> Content on /<?php echo htmlspecialchars($current_channel_code); ?>/ (<?php echo htmlspecialchars($current_channel_display_name); ?>) may be NSFW.
              <button class="nsfw-warning-close" id="nsfw-warning-close" title="Close Warning" aria-label="Close Warning">×</button>
            </div>
          <?php endif; ?>

          <?php if ($viewing_thread_id && $thread_op): // --- Thread View --- ?>
            <div class="thread-view-header">[<a href="./?channel=<?php echo urlencode($current_channel_code); ?>">Return to /<?php echo htmlspecialchars($current_channel_code); ?>/</a>]</div>
            <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?>
              <div class="reply-form-container">
                <h4>Reply to Thread No.<?php echo $viewing_thread_id; ?></h4>
                <form action="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $viewing_thread_id; ?>" method="post" enctype="multipart/form-data">
                  <input type="hidden" name="thread_id" value="<?php echo $viewing_thread_id; ?>">
                  <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                  <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                  <table>
                    <?php if (!$current_user): ?>
                    <tr><th><label for="reply_username">Username</label></th><td><input type="text" name="username" id="reply_username" size="30" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td></tr>
                    <tr><th><label for="reply_password">Password</label></th><td><input type="password" name="password" id="reply_password" size="30"> <small>(Legacy)</small></td></tr>
                    <?php endif; ?>
                    <tr>
                      <th><label for="reply_comment">Comment</label></th>
                      <td>
                        <div class="text-formatter-toolbar">
                          <button type="button" class="format-button" title="Bold" onclick="insertBbCode('reply_comment', 'b')"><b>B</b></button>
                          <button type="button" class="format-button" title="Italic" onclick="insertBbCode('reply_comment', 'i')"><i>I</i></button>
                          <button type="button" class="format-button" title="Strikethrough" onclick="insertBbCode('reply_comment', 's')"><del>S</del></button>
                          <button type="button" class="format-button" title="Spoiler" onclick="insertBbCode('reply_comment', 'spoiler')">Spoiler</button>
                          <button type="button" class="format-button" title="Code" onclick="insertBbCode('reply_comment', 'code')">Code</button>
                          <button type="button" class="format-button" title="Quote" onclick="insertBbCode('reply_comment', 'quote')">Quote</button>
                        </div>
                        <textarea name="comment" id="reply_comment" rows="4" cols="45" required></textarea>
                      </td>
                    </tr>
                    <tr><th><label for="reply_image">File</label></th><td><input type="file" name="image" id="reply_image" accept=".<?php echo implode(',.', ALLOWED_EXTENSIONS); ?>,video/*,audio/*,image/*"></td></tr>
                    <tr><th></th><td><input type="submit" value="Submit Reply"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td></tr>
                  </table>
                </form>
              </div>
            <?php elseif ($current_user && $current_user['status'] === STATUS_BANNED): ?>
              <p class="error">You are banned and cannot reply.</p>
            <?php endif; ?>
            <hr>
            <?php
              // --- Render Thread OP (Thread View) --- (PHP Logic assumed correct)
              $thread = $threads[0];
              $thread_id = $thread['id'];
              $post_element_id = 'post-' . $thread_id;
              $post_media_html = ''; // Generated by PHP
              $user_info = isset($thread['user_id']) && isset($users_data[$thread['user_id']]) ? $users_data[$thread['user_id']] : null;
              $display_name = $user_info ? htmlspecialchars($user_info['username']) : ($thread['username'] ? htmlspecialchars($thread['username']) : 'Anonymous');
              $display_role = $user_info ? $user_info['role'] : null;
              $display_status = $user_info ? $user_info['status'] : null;
              $can_edit_post = true; // Placeholder for PHP logic
              $can_delete_post = true; // Placeholder for PHP logic
              $can_ban_user = true; // Placeholder for PHP logic

              // Simplified media html generation for example
              if ($thread['image']) {
                 $post_media_html .= "<div class='file-info uploaded-file-info'>[Media Placeholder for {$thread['image']}]</div><div class='media-container' style='display:none;'></div>";
              }
              $link_media_result = process_comment_media_links($thread['comment'], $post_element_id); // Assumed PHP function
              $post_media_html .= $link_media_result['media_html'];
              $formatted_comment = format_comment($link_media_result['cleaned_text']); // Assumed PHP function
            ?>
            <div class="thread" id="thread-<?php echo $thread_id; ?>">
              <div class="post op" id="<?php echo $post_element_id; ?>">
                <p class="post-info">
                  <?php if (!empty($thread['subject'])): ?><span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span><?php endif; ?>
                  <span class="name"><?php echo $display_name; ?></span>
                  <?php if ($display_role): ?><span class="role role-<?php echo htmlspecialchars($display_role); ?>">(<?php echo ucfirst(htmlspecialchars($display_role)); ?>)</span><?php endif; ?>
                  <?php if ($display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                  <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                  <span class="post-id">No.<?php echo $thread_id; ?></span>
                  <a href="#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                  <?php // --- Action Links --- ?>
                  <?php if ($can_edit_post): ?>
                    <span class="action-link">[<a href="./?action=show_edit_form&type=thread&id=<?php echo $thread_id; ?>" title="Edit Thread">Edit</a>]</span>
                  <?php endif; ?>
                  <?php if ($can_delete_post): ?>
                    <span class="action-link">[<a href="./?action=confirm_delete&type=thread&id=<?php echo $thread_id; ?>" title="Delete Thread">Delete</a>]</span>
                  <?php endif; ?>
                  <?php if ($can_ban_user && $thread['user_id']): // Added check for user_id existence ?>
                    <span class="action-link">
                      <form action="./" method="post" style="display:inline;">
                        <input type="hidden" name="action" value="<?php echo ($display_status === STATUS_BANNED ? 'unban_user' : 'ban_user'); ?>">
                        <input type="hidden" name="user_id" value="<?php echo $thread['user_id']; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <button type="submit" title="<?php echo ($display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?> User">[<?php echo ($display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?>]</button>
                      </form>
                    </span>
                  <?php endif; ?>
                </p>
                <?php echo $post_media_html; // Assumes PHP generated this correctly ?>
                <div class="comment"><?php echo $formatted_comment; // Assumes PHP generated this correctly ?></div>
              </div><!-- /.post.op -->
              <div class="reply-container">
                <?php // --- Render Replies (Thread View) --- (PHP Logic assumed correct) ?>
                <?php $all_thread_replies = $replies_to_display[$thread_id] ?? []; ?>
                <?php foreach ($all_thread_replies as $reply): ?>
                  <?php
                    $reply_id = $reply['id'];
                    $reply_element_id = 'post-' . $reply_id;
                    $reply_media_html = ''; // Generated by PHP
                    $reply_user_info = isset($reply['user_id']) && isset($users_data[$reply['user_id']]) ? $users_data[$reply['user_id']] : null;
                    $reply_display_name = $reply_user_info ? htmlspecialchars($reply_user_info['username']) : ($reply['username'] ? htmlspecialchars($reply['username']) : 'Anonymous');
                    $reply_display_role = $reply_user_info ? $reply_user_info['role'] : null;
                    $reply_display_status = $reply_user_info ? $reply_user_info['status'] : null;
                    $can_edit_reply = true; // Placeholder for PHP logic
                    $can_delete_reply = true; // Placeholder for PHP logic
                    $can_ban_reply_user = true; // Placeholder for PHP logic

                    // Simplified media html generation for example
                    if ($reply['image']) {
                       $reply_media_html .= "<div class='file-info uploaded-file-info'>[Media Placeholder for {$reply['image']}]</div><div class='media-container' style='display:none;'></div>";
                    }
                    $reply_link_media_result = process_comment_media_links($reply['comment'], $reply_element_id); // Assumed PHP function
                    $reply_media_html .= $reply_link_media_result['media_html'];
                    $reply_formatted_comment = format_comment($reply_link_media_result['cleaned_text']); // Assumed PHP function
                  ?>
                  <div class="reply" id="<?php echo $reply_element_id; ?>">
                    <p class="post-info">
                      <span class="name"><?php echo $reply_display_name; ?></span>
                      <?php if ($reply_display_role): ?><span class="role role-<?php echo htmlspecialchars($reply_display_role); ?>">(<?php echo ucfirst(htmlspecialchars($reply_display_role)); ?>)</span><?php endif; ?>
                      <?php if ($reply_display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                      <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                      <span class="post-id">No.<?php echo $reply_id; ?></span>
                      <a href="#<?php echo $reply_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                      <?php // --- Reply Action Links --- ?>
                      <?php if ($can_edit_reply): ?>
                        <span class="action-link">[<a href="./?action=show_edit_form&type=reply&id=<?php echo $reply_id; ?>" title="Edit Reply">Edit</a>]</span>
                      <?php endif; ?>
                      <?php if ($can_delete_reply): ?>
                        <span class="action-link">[<a href="./?action=confirm_delete&type=reply&id=<?php echo $reply_id; ?>" title="Delete Reply">Delete</a>]</span>
                      <?php endif; ?>
                      <?php if ($can_ban_reply_user && $reply['user_id']): // Added check for user_id existence ?>
                        <span class="action-link">
                          <form action="./" method="post" style="display:inline;">
                            <input type="hidden" name="action" value="<?php echo ($reply_display_status === STATUS_BANNED ? 'unban_user' : 'ban_user'); ?>">
                            <input type="hidden" name="user_id" value="<?php echo $reply['user_id']; ?>">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit" title="<?php echo ($reply_display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?> User">[<?php echo ($reply_display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?>]</button>
                          </form>
                        </span>
                      <?php endif; ?>
                    </p>
                    <?php echo $reply_media_html; // Assumes PHP generated this correctly ?>
                    <div class="comment"><?php echo $reply_formatted_comment; // Assumes PHP generated this correctly ?></div>
                  </div><!-- /.reply -->
                <?php endforeach; ?>
                <?php if (empty($all_thread_replies)): ?>
                  <p style="text-align: center; color: #aaa; margin-top: 15px;">No replies yet.</p>
                <?php endif; ?>
              </div><!-- /.reply-container -->
            </div><!-- /.thread -->
            <hr>

          <?php else: // --- Board View --- ?>
            <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?>
              <div class="post-form" id="post-form">
                <h2>Post new thread in /<?php echo htmlspecialchars($current_channel_code); ?>/</h2>
                <button id="togglePostFormButton" class="toggle-button" type="button">Show Form</button>
                <div id="postFormContent" class="post-form-content" style="display: none;">
                  <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                    <input type="hidden" name="form_type" value="new_thread">
                    <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <table>
                      <?php if (!$current_user): ?>
                      <tr><th><label for="username">Username</label></th><td><input type="text" name="username" id="username" size="30" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td></tr>
                      <tr><th><label for="password">Password</label></th><td><input type="password" name="password" id="password" size="30"> <small>(Legacy)</small></td></tr>
                      <?php endif; ?>
                      <tr><th><label for="subject">Subject</label></th><td><input type="text" name="subject" id="subject" size="30"></td></tr>
                      <tr>
                        <th><label for="comment">Comment</label></th>
                        <td>
                          <div class="text-formatter-toolbar">
                            <button type="button" class="format-button" title="Bold" onclick="insertBbCode('comment', 'b')"><b>B</b></button>
                            <button type="button" class="format-button" title="Italic" onclick="insertBbCode('comment', 'i')"><i>I</i></button>
                            <button type="button" class="format-button" title="Strikethrough" onclick="insertBbCode('comment', 's')"><del>S</del></button>
                            <button type="button" class="format-button" title="Spoiler" onclick="insertBbCode('comment', 'spoiler')">Spoiler</button>
                            <button type="button" class="format-button" title="Code" onclick="insertBbCode('comment', 'code')">Code</button>
                            <button type="button" class="format-button" title="Quote" onclick="insertBbCode('comment', 'quote')">Quote</button>
                            <!-- Add more buttons if needed -->
                          </div>
                          <textarea name="comment" id="comment" rows="5" cols="50" required></textarea>
                        </td>
                      </tr>
                      <tr><th><label for="image">File</label></th><td><input type="file" name="image" id="image" accept=".<?php echo implode(',.', ALLOWED_EXTENSIONS); ?>,video/*,audio/*,image/*"></td></tr>
                      <tr><th></th><td><input type="submit" value="Submit Thread"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td></tr>
                    </table>
                  </form>
                </div>
              </div>
            <?php elseif ($current_user && $current_user['status'] === STATUS_BANNED): ?>
              <p class="error">You are banned and cannot post new threads.</p>
            <?php endif; ?>
            <hr>
            <?php if ($total_threads == 0): ?>
              <p style="text-align: center; color: #aaa; margin-top: 30px;">No threads in /<?php echo htmlspecialchars($current_channel_code); ?>/ yet.</p>
            <?php else: ?>
              <div class="pagination">
                <?php if ($current_page > 1) : ?>
                  <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a>
                <?php else : ?>
                  <span class="disabled"><< Prev</span>
                <?php endif; ?>
                <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
                <?php if ($current_page < $total_pages) : ?>
                  <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a>
                <?php else : ?>
                  <span class="disabled">Next >></span>
                <?php endif; ?>
              </div>
              <hr>
              <?php // --- Render Threads (Board View) --- (PHP Logic assumed correct) ?>
              <?php foreach ($threads as $thread): ?>
                <?php
                  $thread_id = $thread['id'];
                  $post_element_id = 'post-' . $thread_id;
                  $thread_replies_preview = $replies_to_display[$thread_id] ?? [];
                  $total_reply_count = $reply_counts[$thread_id] ?? 0;
                  $omitted_count = max(0, $total_reply_count - count($thread_replies_preview));
                  $thread_media_html = ''; // Generated by PHP
                  $user_info = isset($thread['user_id']) && isset($users_data[$thread['user_id']]) ? $users_data[$thread['user_id']] : null;
                  $display_name = $user_info ? htmlspecialchars($user_info['username']) : ($thread['username'] ? htmlspecialchars($thread['username']) : 'Anonymous');
                  $display_role = $user_info ? $user_info['role'] : null;
                  $display_status = $user_info ? $user_info['status'] : null;
                  $can_edit_post = true; // Placeholder
                  $can_delete_post = true; // Placeholder
                  $can_ban_user = true; // Placeholder

                  // Simplified media html generation for example
                  if ($thread['image']) {
                     $thread_media_html .= "<div class='file-info uploaded-file-info'>[Media Placeholder for {$thread['image']}]</div><div class='media-container' style='display:none;'></div>";
                  }
                  $link_media_result = process_comment_media_links($thread['comment'], $post_element_id); // Assumed PHP function
                  $thread_media_html .= $link_media_result['media_html'];
                  $cleaned_comment = $link_media_result['cleaned_text'];
                  $formatted_comment = format_comment($cleaned_comment); // Assumed PHP function
                  $display_comment_html = ''; $full_comment_id = 'full-comment-' . $post_element_id;
                  if (mb_strlen(strip_tags($thread['comment'])) > COMMENT_PREVIEW_LENGTH) {
                     $truncated_cleaned = mb_substr($cleaned_comment, 0, COMMENT_PREVIEW_LENGTH) . '...'; // Simplified truncation
                     $truncated_formatted = format_comment($truncated_cleaned); // Format truncated
                     $display_comment_html = "<div class='comment-truncated'>{$truncated_formatted} <br><button class='show-full-text-btn' data-target-id='{$full_comment_id}'>View Full Text</button></div><div id='{$full_comment_id}' class='comment-full'>{$formatted_comment}</div>";
                  } else { $display_comment_html = $formatted_comment; }
                ?>
                <div class="thread" id="thread-<?php echo $thread_id; ?>">
                  <div class="post op" id="<?php echo $post_element_id; ?>">
                    <p class="post-info">
                      <?php if (!empty($thread['subject'])): ?><span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span><?php endif; ?>
                      <span class="name"><?php echo $display_name; ?></span>
                      <?php if ($display_role): ?><span class="role role-<?php echo htmlspecialchars($display_role); ?>">(<?php echo ucfirst(htmlspecialchars($display_role)); ?>)</span><?php endif; ?>
                      <?php if ($display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                      <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                      <span class="post-id">No.<?php echo $thread_id; ?></span>
                      <span class="reply-link">[<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>" title="View Thread">View</a>]</span>
                      <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?>
                      <span class="reply-link">[<a href="#reply-form-<?php echo $thread_id; ?>" title="Quick Reply">Reply</a>]</span>
                      <?php endif; ?>
                      <?php if ($total_reply_count > 0): ?><span class="reply-count">(<?php echo $total_reply_count; ?> replies)</span><?php endif; ?>
                      <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                      <?php // --- OP Action Links (Board View) --- ?>
                      <?php if ($can_edit_post): ?> <span class="action-link">[<a href="./?action=show_edit_form&type=thread&id=<?php echo $thread_id; ?>">Edit</a>]</span> <?php endif; ?>
                      <?php if ($can_delete_post): ?> <span class="action-link">[<a href="./?action=confirm_delete&type=thread&id=<?php echo $thread_id; ?>">Delete</a>]</span> <?php endif; ?>
                      <?php if ($can_ban_user && $thread['user_id']): ?>
                        <span class="action-link">
                          <form action="./" method="post" style="display:inline;">
                            <input type="hidden" name="action" value="<?php echo ($display_status === STATUS_BANNED ? 'unban_user' : 'ban_user'); ?>">
                            <input type="hidden" name="user_id" value="<?php echo $thread['user_id']; ?>">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit" title="<?php echo ($display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?> User">[<?php echo ($display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?>]</button>
                          </form>
                        </span>
                      <?php endif; ?>
                    </p>
                    <?php echo $thread_media_html; // Assumes PHP generated this correctly ?>
                    <div class="comment"><?php echo $display_comment_html; // Assumes PHP generated/truncated this correctly ?></div>
                  </div><!-- /.post.op -->

                  <?php // --- Quick Reply Form (Board View) --- ?>
                  <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?>
                    <div class="reply-form-container" id="reply-form-<?php echo $thread_id; ?>" style="display: none;">
                      <h4>Reply to Thread No.<?php echo $thread_id; ?></h4>
                      <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                        <input type="hidden" name="thread_id" value="<?php echo $thread_id; ?>">
                        <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <table>
                          <?php if (!$current_user): ?>
                          <tr><th><label for="reply_username_q_<?php echo $thread_id; ?>">Username</label></th><td><input type="text" name="username" id="reply_username_q_<?php echo $thread_id; ?>" size="30" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td></tr>
                          <tr><th><label for="reply_password_q_<?php echo $thread_id; ?>">Password</label></th><td><input type="password" name="password" id="reply_password_q_<?php echo $thread_id; ?>" size="30"> <small>(Legacy)</small></td></tr>
                          <?php endif; ?>
                          <tr>
                            <th><label for="reply_comment_<?php echo $thread_id; ?>">Comment</label></th>
                            <td>
                              <?php $quickReplyTextareaId = 'reply_comment_' . $thread_id; ?>
                              <div class="text-formatter-toolbar">
                                <button type="button" class="format-button" title="Bold" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'b')"><b>B</b></button>
                                <button type="button" class="format-button" title="Italic" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'i')"><i>I</i></button>
                                <button type="button" class="format-button" title="Strikethrough" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 's')"><del>S</del></button>
                                <button type="button" class="format-button" title="Spoiler" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'spoiler')">Spoiler</button>
                                <button type="button" class="format-button" title="Code" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'code')">Code</button>
                                <button type="button" class="format-button" title="Quote" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'quote')">Quote</button>
                              </div>
                              <textarea name="comment" id="<?php echo $quickReplyTextareaId; ?>" rows="4" cols="45" required></textarea>
                            </td>
                          </tr>
                          <tr><th><label for="reply_image_<?php echo $thread_id; ?>">File</label></th><td><input type="file" name="image" id="reply_image_<?php echo $thread_id; ?>" accept=".<?php echo implode(',.', ALLOWED_EXTENSIONS); ?>,video/*,audio/*,image/*"></td></tr>
                          <tr><th></th><td><input type="submit" value="Submit Reply"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td></tr>
                        </table>
                      </form>
                    </div>
                  <?php endif; ?>

                  <div class="reply-container">
                    <?php if ($omitted_count > 0): ?>
                      <p class="omitted-posts"><?php echo $omitted_count; ?> replies omitted. [<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>">View Full Thread</a>]</p>
                    <?php endif; ?>
                    <?php // --- Render Reply Previews (Board View) --- (PHP Logic assumed correct) ?>
                    <?php foreach ($thread_replies_preview as $reply): ?>
                      <?php
                        $reply_id = $reply['id'];
                        $reply_element_id = 'post-' . $reply_id;
                        $reply_media_html = ''; // Generated by PHP
                        $reply_user_info = isset($reply['user_id']) && isset($users_data[$reply['user_id']]) ? $users_data[$reply['user_id']] : null;
                        $reply_display_name = $reply_user_info ? htmlspecialchars($reply_user_info['username']) : ($reply['username'] ? htmlspecialchars($reply['username']) : 'Anonymous');
                        $reply_display_role = $reply_user_info ? $reply_user_info['role'] : null;
                        $reply_display_status = $reply_user_info ? $reply_user_info['status'] : null;
                        $can_edit_reply = true; // Placeholder
                        $can_delete_reply = true; // Placeholder
                        $can_ban_reply_user = true; // Placeholder

                        // Simplified media html generation for example
                        if ($reply['image']) {
                           $reply_media_html .= "<div class='file-info uploaded-file-info'>[Media Placeholder for {$reply['image']}]</div><div class='media-container' style='display:none;'></div>";
                        }
                        $reply_link_media_result = process_comment_media_links($reply['comment'], $reply_element_id); // Assumed PHP function
                        $reply_media_html .= $reply_link_media_result['media_html'];
                        $reply_cleaned_comment = $reply_link_media_result['cleaned_text'];
                        $reply_formatted_comment = format_comment($reply_cleaned_comment); // Assumed PHP function
                        $reply_display_comment_html = ''; $reply_full_comment_id = 'full-comment-' . $reply_element_id;
                        if (mb_strlen(strip_tags($reply['comment'])) > COMMENT_PREVIEW_LENGTH) {
                          $reply_truncated_cleaned = mb_substr($reply_cleaned_comment, 0, COMMENT_PREVIEW_LENGTH) . '...'; // Simplified truncation
                          $reply_truncated_formatted = format_comment($reply_truncated_cleaned); // Format truncated
                          $reply_display_comment_html = "<div class='comment-truncated'>{$reply_truncated_formatted}<br><button class='show-full-text-btn' data-target-id='{$reply_full_comment_id}'>View Full Text</button></div><div id='{$reply_full_comment_id}' class='comment-full'>{$reply_formatted_comment}</div>";
                        } else { $reply_display_comment_html = $reply_formatted_comment; }
                      ?>
                      <div class="reply" id="<?php echo $reply_element_id; ?>">
                        <p class="post-info">
                          <span class="name"><?php echo $reply_display_name; ?></span>
                          <?php if ($reply_display_role): ?><span class="role role-<?php echo htmlspecialchars($reply_display_role); ?>">(<?php echo ucfirst(htmlspecialchars($reply_display_role)); ?>)</span><?php endif; ?>
                          <?php if ($reply_display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                          <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                          <span class="post-id">No.<?php echo $reply_id; ?></span>
                          <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>#<?php echo $reply_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                          <?php // --- Reply Preview Action Links --- ?>
                          <?php if ($can_edit_reply): ?> <span class="action-link">[<a href="./?action=show_edit_form&type=reply&id=<?php echo $reply_id; ?>">Edit</a>]</span> <?php endif; ?>
                          <?php if ($can_delete_reply): ?> <span class="action-link">[<a href="./?action=confirm_delete&type=reply&id=<?php echo $reply_id; ?>">Delete</a>]</span> <?php endif; ?>
                          <?php if ($can_ban_reply_user && $reply['user_id']): ?>
                            <span class="action-link">
                              <form action="./" method="post" style="display:inline;">
                                <input type="hidden" name="action" value="<?php echo ($reply_display_status === STATUS_BANNED ? 'unban_user' : 'ban_user'); ?>">
                                <input type="hidden" name="user_id" value="<?php echo $reply['user_id']; ?>">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" title="<?php echo ($reply_display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?> User">[<?php echo ($reply_display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?>]</button>
                              </form>
                            </span>
                          <?php endif; ?>
                        </p>
                        <?php echo $reply_media_html; // Assumes PHP generated this correctly ?>
                        <div class="comment"><?php echo $reply_display_comment_html; // Assumes PHP generated/truncated this correctly ?></div>
                      </div><!-- /.reply -->
                    <?php endforeach; ?>
                  </div><!-- /.reply-container -->
                </div><!-- /.thread -->
                <hr>
              <?php endforeach; ?>
              <div class="pagination">
                <?php if ($current_page > 1) : ?>
                  <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a>
                <?php else : ?>
                  <span class="disabled"><< Prev</span>
                <?php endif; ?>
                <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
                <?php if ($current_page < $total_pages) : ?>
                  <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a>
                <?php else : ?>
                  <span class="disabled">Next >></span>
                <?php endif; ?>
              </div>
            <?php endif; // End check for total_threads > 0 ?>
          <?php endif; // End board/thread view switch ?>
        <?php endif; // End check for current_channel_code exists ?>
      <?php endif; // End check for fetch_page_data ?>

    </div> <!-- /.container -->
  </body>
</html>