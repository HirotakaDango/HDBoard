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
define('PASSWORD_MIN_LENGTH', 8); // Increased for better security

// User Roles
define('ROLE_USER', 'user');
define('ROLE_JANITOR', 'janitor');
define('ROLE_MODERATOR', 'moderator');
define('ROLE_ADMIN', 'admin');
$roles = [ROLE_USER, ROLE_JANITOR, ROLE_MODERATOR, ROLE_ADMIN];
$role_hierarchy = [
  ROLE_USER => 1,
  ROLE_JANITOR => 2,
  ROLE_MODERATOR => 3,
  ROLE_ADMIN => 4
];

// User Statuses
define('STATUS_ACTIVE', 'active');
define('STATUS_BANNED', 'banned');
$statuses = [STATUS_ACTIVE, STATUS_BANNED];

// --- Initialization & DB Setup ---
ini_set('display_errors', 0); // Hide errors from users
error_reporting(E_ALL);

// Configure session settings for better security
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
  ini_set('session.cookie_secure', 1);
}
ini_set('session.cookie_samesite', 'Lax'); // Prevent CSRF via cross-site cookies

if (session_status() === PHP_SESSION_NONE) {
  session_start();
}

if (!isset($_SESSION['session_started_time'])) {
  $_SESSION['session_started_time'] = time();
}
if (!isset($_SESSION['last_regen']) || time() - $_SESSION['last_regen'] > (15 * 60)) {
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
  http_response_code(403);
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
  if (!mkdir(UPLOADS_DIR, 0755, true)) { die("Error: Could not create base uploads directory."); }
}
if (!is_writable(UPLOADS_DIR)) { die("Error: The base uploads directory is not writable."); }

// --- Database Connection and Schema Update ---
try {
  $db = new PDO('sqlite:' . DB_FILE);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
  $db->exec('PRAGMA foreign_keys = ON;');

  // --- Users Table ---
  $db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '" . ROLE_USER . "',
    status TEXT NOT NULL DEFAULT '" . STATUS_ACTIVE . "',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK(role IN ('" . implode("','", $roles) . "')),
    CHECK(status IN ('" . implode("','", $statuses) . "'))
  )");

  // --- Threads Table ---
  $db->exec("CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    user_id INTEGER DEFAULT NULL,
    username TEXT DEFAULT NULL,
    password_hash TEXT DEFAULT NULL,
    subject TEXT,
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_reply_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  )");

  // --- Replies Table ---
  $db->exec("CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    user_id INTEGER DEFAULT NULL,
    username TEXT DEFAULT NULL,
    password_hash TEXT DEFAULT NULL,
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  )");

  function addColumnIfNotExists(PDO $db, string $tableName, string $columnName, string $columnDefinition) {
    try {
      $stmt = $db->query("PRAGMA table_info($tableName)");
      $columns = $stmt->fetchAll(PDO::FETCH_COLUMN, 1);
      if (!in_array($columnName, $columns)) {
        $db->exec("ALTER TABLE $tableName ADD COLUMN $columnName $columnDefinition");
      }
    } catch (PDOException $e) {
      error_log("Schema Update Error (Table: $tableName, Column: $columnName): " . $e->getMessage());
    }
  }

  addColumnIfNotExists($db, 'threads', 'user_id', 'INTEGER DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL');
  addColumnIfNotExists($db, 'replies', 'user_id', 'INTEGER DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL');
  addColumnIfNotExists($db, 'threads', 'username', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'threads', 'password_hash', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'replies', 'username', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'replies', 'password_hash', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'users', 'role', "TEXT NOT NULL DEFAULT '" . ROLE_USER . "' CHECK(role IN ('" . implode("','", $roles) . "'))");
  addColumnIfNotExists($db, 'users', 'status', "TEXT NOT NULL DEFAULT '" . STATUS_ACTIVE . "' CHECK(status IN ('" . implode("','", $statuses) . "'))");

} catch (PDOException $e) {
  error_log("Database Connection/Setup Error: " . $e->getMessage());
  die("A critical error occurred with the database connection. Please check server logs.");
}

// --- Helper Functions ---
function is_logged_in(): bool {
  return isset($_SESSION['user_id']);
}

function get_current_user(): ?array {
  if (!is_logged_in() || !isset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['role'], $_SESSION['status'])) {
    return null;
  }
  return [
    'id' => $_SESSION['user_id'],
    'username' => $_SESSION['username'],
    'role' => $_SESSION['role'],
    'status' => $_SESSION['status'],
  ];
}

function logout_user() {
  $_SESSION = [];
  if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
      $params["path"], $params["domain"],
      $params["secure"], $params["httponly"]
    );
  }
  session_destroy();
}

function user_has_role(string $required_role): bool {
  global $role_hierarchy;
  $user = get_current_user();
  if (!$user || !isset($role_hierarchy[$user['role']], $role_hierarchy[$required_role])) {
    return false;
  }
  return $role_hierarchy[$user['role']] >= $role_hierarchy[$required_role];
}

function verify_legacy_user_password(PDO $db, string $raw_username, string $submitted_password): bool {
  if (empty($raw_username) || empty($submitted_password)) {
    return false;
  }
  try {
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
    $existing_hash = $result['password_hash'] ?? null;

    if ($existing_hash === null) return false;
    return password_verify($submitted_password, $existing_hash);
  } catch (PDOException $e) {
    error_log("Legacy password verification DB error for '{$raw_username}': " . $e->getMessage());
    return false;
  }
}

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

function get_user_by_id(PDO $db, int $user_id): ?array {
  try {
    $stmt = $db->prepare("SELECT id, username, role, status, created_at FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    return $stmt->fetch() ?: null;
  } catch (PDOException $e) {
    error_log("Error fetching user by ID '{$user_id}': " . $e->getMessage());
    return null;
  }
}

function delete_post_file(?string $image_relative_path): bool {
  if (empty($image_relative_path)) {
    return true;
  }
  if (strpos($image_relative_path, '..') !== false) {
    error_log("Attempted deletion with traversal path: " . $image_relative_path);
    return false;
  }
  $full_path = UPLOADS_DIR . DIRECTORY_SEPARATOR . $image_relative_path;
  $base_dir = realpath(UPLOADS_DIR);
  $real_file_path = realpath($full_path);
  if ($real_file_path === false || strpos($real_file_path, $base_dir) !== 0) {
    error_log("Attempted to delete invalid or non-existent file (path check failed): " . $full_path);
    return false;
  }
  if (is_writable($real_file_path)) {
    if (@unlink($real_file_path)) {
      return true;
    }
    error_log("Failed to delete file: " . $real_file_path);
  } else {
    error_log("File not writable, cannot delete: " . $real_file_path);
  }
  return false;
}

function handle_upload($file_input_name) {
  if (!isset($_FILES[$file_input_name]) || $_FILES[$file_input_name]['error'] === UPLOAD_ERR_NO_FILE) {
    return ['success' => false];
  }
  $file = $_FILES[$file_input_name];

  if ($file['error'] !== UPLOAD_ERR_OK) {
    $errors = [
      UPLOAD_ERR_INI_SIZE => 'File is too large (Server limit).',
      UPLOAD_ERR_FORM_SIZE => 'File is too large (Form limit).',
      UPLOAD_ERR_PARTIAL => 'File was only partially uploaded.',
      UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder.',
      UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
      UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the upload.'
    ];
    return ['error' => $errors[$file['error']] ?? 'Unknown upload error (Code: ' . $file['error'] . ').'];
  }
  if ($file['size'] > MAX_FILE_SIZE) {
    return ['error' => 'File is too large (Max: ' . (MAX_FILE_SIZE / 1024 / 1024) . ' MB).'];
  }

  $file_info = pathinfo($file['name']);
  $extension = strtolower($file_info['extension'] ?? '');
  if (!in_array($extension, ALLOWED_EXTENSIONS)) {
    return ['error' => 'Invalid file extension.'];
  }
  
  $img_w = null; $img_h = null;
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
    $image_size = @getimagesize($file['tmp_name']);
    if ($image_size !== false) {
      $img_w = $image_size[0] ?? null;
      $img_h = $image_size[1] ?? null;
    }
  }

  $relative_dir_path = date('Y/m/d');
  $target_dir = UPLOADS_DIR . '/' . $relative_dir_path;
  if (!is_dir($target_dir)) {
    if (!mkdir($target_dir, 0755, true)) {
      error_log("Error: Could not create dated upload directory: " . $target_dir);
      return ['error' => 'Server error: Could not create upload directory.'];
    }
  }
  if (!is_writable($target_dir)) {
    error_log("Error: Dated upload directory is not writable: " . $target_dir);
    return ['error' => 'Server error: Upload directory is not writable.'];
  }

  $new_filename = uniqid('', true) . '.' . $extension;
  $relative_path_for_db = $relative_dir_path . '/' . $new_filename;
  $destination = $target_dir . '/' . $new_filename;

  if (move_uploaded_file($file['tmp_name'], $destination)) {
    if (!file_exists($destination)) {
      error_log("Failed to confirm uploaded file existence: " . $destination);
      return ['error' => 'Failed to confirm file after move.'];
    }
    return [ 'success' => true, 'filename' => $relative_path_for_db, 'orig_name' => basename($file['name']), 'width' => $img_w, 'height' => $img_h ];
  }
  error_log("Failed to move uploaded file to " . $destination);
  return ['error' => 'Failed to save uploaded file.'];
}

function get_render_media_type($url_or_filename) {
  if (!$url_or_filename) return 'unknown';

  $is_url = preg_match('/^(https?|ftp):\/\//i', $url_or_filename);
  if ($is_url) {
    $youtube_regex = '/^https?:\/\/(?:www\.)?(?:m\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})(?:[?&].*)?$/i';
    if (preg_match($youtube_regex, $url_or_filename)) { return 'youtube'; }
  }
  $path_part = $is_url ? parse_url($url_or_filename, PHP_URL_PATH) : $url_or_filename;
  $extension = strtolower(pathinfo($path_part ?: '', PATHINFO_EXTENSION));

  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
  if (in_array($extension, VIDEO_EXTENSIONS)) return 'video';
  if (in_array($extension, AUDIO_EXTENSIONS)) return 'audio';
  return 'unknown';
}

function format_comment($comment) {
  $comment = (string) ($comment ?? '');
  $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');

  $comment = preg_replace('/\[b\](.*?)\[\/b\]/is', '<strong>$1</strong>', $comment);
  $comment = preg_replace('/\[i\](.*?)\[\/i\]/is', '<em>$1</em>', $comment);
  $comment = preg_replace('/\[u\](.*?)\[\/u\]/is', '<u>$1</u>', $comment);
  $comment = preg_replace('/\[s\](.*?)\[\/s\]/is', '<del>$1</del>', $comment);
  $comment = preg_replace('/\[spoiler\](.*?)\[\/spoiler\]/is', '<span class="spoiler">$1</span>', $comment);
  $comment = preg_replace_callback('/\[code\](.*?)\[\/code\]/is', function ($matches) {
    $code_content = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
    return '<pre class="code-block"><code>' . $code_content . '</code></pre>';
  }, $comment);
  $comment = preg_replace('/\[quote\](.*?)\[\/quote\]/is', '<blockquote class="quote-block">$1</blockquote>', $comment);
  $comment = preg_replace_callback('/\[quote=(?:&quot;)?(.*?)(?:&quot;)?\](.*?)\[\/quote\]/is', function ($matches) {
    $cite_attr = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
    return '<blockquote class="quote-block"><cite>Quote from ' . $cite_attr . ':</cite>' . $matches[2] . '</blockquote>';
  }, $comment);

  $comment = preg_replace_callback(
    '/(?<!["\'>=])\b(https?|ftp):\/\/([^\s<>"\'`]+)/i',
    function ($matches) {
      $url = $matches[0];
      $display_path = htmlspecialchars_decode($matches[2], ENT_QUOTES);
      $display_url = (mb_strlen($display_path) > 50) ? mb_substr($display_path, 0, 47) . '...' : $display_path;
      $safe_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
      $safe_display_url = htmlspecialchars($matches[1] . '://' . $display_url, ENT_QUOTES, 'UTF-8');
      return '<a href="' . $safe_url . '" target="_blank" rel="noopener noreferrer">' . $safe_display_url . '</a>';
    },
    $comment
  );

  $comment = nl2br($comment, false);
  $comment = preg_replace_callback('/(<pre(?:.*?)>)(.*?)(<\/pre>)/is', fn($m) => $m[1] . str_replace('<br />', '', $m[2]) . $m[3], $comment);
  $comment = preg_replace_callback('/(<blockquote(?:.*?)>)(.*?)(<\/blockquote>)/is', fn($m) => $m[1] . str_replace('<br />', '', $m[2]) . $m[3], $comment);

  $comment = preg_replace('/(^<br\s*\/?>|^)(>[^<].*?)(?=<br\s*\/?>|\n|$)/m', '$1<span class="greentext">$2</span>', $comment);
  $comment = preg_replace('/^(>[^<].*?)(?=<br\s*\/?>|\n|$)/m', '<span class="greentext">$1</span>', $comment);
  $comment = preg_replace('/>>(\d+)/', '<a href="#post-$1" class="reply-mention">>>$1</a>', $comment);

  return $comment;
}

function generate_uploaded_media_html(array $post_data, string $post_element_id_prefix): string {
  if (empty($post_data['image'])) return '';
  $relative_path = $post_data['image'];
  $media_url = UPLOADS_URL_PATH . '/' . $relative_path;
  $safe_media_url = htmlspecialchars($media_url, ENT_QUOTES, 'UTF-8');
  $safe_orig_name = htmlspecialchars($post_data['image_orig_name'] ?? basename($relative_path), ENT_QUOTES, 'UTF-8');
  $media_type = get_render_media_type($relative_path);
  $media_id = $post_element_id_prefix . '-uploaded-media';
  $details = "File: <a href='{$safe_media_url}' target='_blank' rel='noopener noreferrer'>{$safe_orig_name}</a>";
  if (!empty($post_data['image_w']) && !empty($post_data['image_h'])) {
    $details .= " ({$post_data['image_w']}x{$post_data['image_h']})";
  }
  $full_file_path = UPLOADS_DIR . '/' . $relative_path;
  if (file_exists($full_file_path)) {
    $file_size = @filesize($full_file_path);
    if ($file_size !== false) {
      $details .= ' (' . round($file_size / 1024, 2) . ' KB)';
    }
  }
  $button_text_map = ['image' => 'View Image', 'video' => 'View Video', 'audio' => 'View Audio'];
  $button_text = $button_text_map[$media_type] ?? 'View Media';
  $html = "<div class='file-info uploaded-file-info'>";
  $html .= "<div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_id}' data-media-url='{$safe_media_url}' data-media-type='{$media_type}'>{$button_text}</button></div>";
  $html .= "<span class='file-details'>{$details}</span>";
  $html .= "</div>";
  $html .= "<div id='media-container-{$media_id}' class='media-container' style='display:none;'></div>";
  return $html;
}

function process_comment_media_links($text, $post_element_id_prefix) {
  $media_html = '';
  $cleaned_text = $text;
  $link_counter = 0;
  $url_regex = '/(?<!href=["\'])(?<!src=["\'])(?<!data-media-url=["\'])(?<!>)\b(https?|ftp):\/\/([^\s<>"\'`]+)/i';

  if (preg_match_all($url_regex, $text, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
    $matches_reversed = array_reverse($matches);
    $media_items_to_append = [];
    foreach ($matches_reversed as $match) {
      $url = $match[0][0];
      $offset = $match[0][1];
      $render_type = get_render_media_type($url);
      if ($render_type !== 'unknown') {
        $media_items_to_append[] = ['url' => $url, 'render_type' => $render_type];
        $cleaned_text = mb_substr($cleaned_text, 0, $offset, 'UTF-8') . mb_substr($cleaned_text, $offset + mb_strlen($url, 'UTF-8'), null, 'UTF-8');
      }
    }
    foreach (array_reverse($media_items_to_append) as $item) {
      $link_counter++;
      $media_id = $post_element_id_prefix . '-link-' . $link_counter;
      $safe_url = htmlspecialchars($item['url'], ENT_QUOTES, 'UTF-8');
      $render_type = $item['render_type'];
      $button_text_map = ['image' => 'View Image', 'video' => 'View Video', 'audio' => 'View Audio', 'youtube' => 'View YouTube'];
      $button_text = $button_text_map[$render_type] ?? 'View Media';
      $media_html .= "<div class='file-info comment-link-info'>";
      $media_html .= "<div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_id}' data-media-url='{$safe_url}' data-media-type='{$render_type}'>{$button_text}</button></div>";
      $safe_display_link = htmlspecialchars($item['url'], ENT_QUOTES, 'UTF-8');
      $media_html .= "<span class='file-details'>Link: <a href='{$safe_url}' target='_blank' rel='noopener noreferrer'>{$safe_display_link}</a></span>";
      $media_html .= "</div>";
      $media_html .= "<div id='media-container-{$media_id}' class='media-container' style='display:none;'></div>";
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
$show_login_form = isset($_GET['action']) && $_GET['action'] === 'login';
$show_register_form = isset($_GET['action']) && $_GET['action'] === 'register';

// --- Global Variables for Actions/Messages ---
$action_error = null; $action_success = null; $auth_error = null; $auth_success = null;
$show_action_form = null; $post_data_for_form = null;

// --- Handle AUTH Actions (Login, Logout, Register, Ban/Unban) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
  $action = $_POST['action'];
  $submitted_csrf = $_POST['csrf_token'] ?? null;
  if (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf)) {
    $temp_error = "Invalid form submission. Please try again.";
    if (in_array($action, ['dologin', 'doregister', 'logout'])) $auth_error = $temp_error;
    else $action_error = $temp_error;
    $action = null;
    error_log("CSRF token mismatch for action: " . ($_POST['action'] ?? 'UNKNOWN'));
  }

  if ($action !== null) {
    switch ($action) {
      case 'dologin':
        $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
        if ($_SESSION['login_attempts'] > 5 && (time() - ($_SESSION['last_login_attempt'] ?? 0)) < 300) {
          $auth_error = "Too many failed login attempts. Please wait 5 minutes.";
        } else {
          $username = trim($_POST['username'] ?? '');
          $password = $_POST['password'] ?? '';
          if (empty($username) || empty($password)) {
            $auth_error = "Username and password are required.";
          } else {
            $user = get_user_by_username($db, $username);
            if ($user && password_verify($password, $user['password_hash'])) {
              if ($user['status'] === STATUS_BANNED) {
                $auth_error = "This account is banned.";
              } else {
                unset($_SESSION['login_attempts'], $_SESSION['last_login_attempt']);
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['status'] = $user['status'];
                $_SESSION['last_regen'] = time();
                header("Location: ./");
                exit;
              }
            } else {
              $_SESSION['last_login_attempt'] = time();
              $auth_error = "Invalid username or password.";
            }
          }
        }
        $show_login_form = true;
        break;

      case 'doregister':
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $password_confirm = $_POST['password_confirm'] ?? '';
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
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user_id;
                $_SESSION['username'] = $username;
                $_SESSION['role'] = ROLE_USER;
                $_SESSION['status'] = STATUS_ACTIVE;
                $_SESSION['last_regen'] = time();
                header("Location: ./");
                exit;
              } catch (PDOException $e) {
                if (str_contains($e->getMessage(), 'UNIQUE constraint failed')) {
                  $auth_error = "Username already taken.";
                } else {
                  $auth_error = "Database error during registration.";
                  error_log("Registration DB error for '{$username}': " . $e->getMessage());
                }
              }
            }
          }
        }
        if ($auth_error) $show_register_form = true;
        break;

      case 'logout':
        logout_user();
        header("Location: ./?loggedout=1");
        exit;

      case 'ban_user':
      case 'unban_user':
        $current_user = get_current_user();
        if (!$current_user || !user_has_role(ROLE_JANITOR)) {
          $action_error = "Permission denied.";
        } else {
          $user_id_to_modify = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
          if (!$user_id_to_modify) {
            $action_error = "Invalid user ID specified.";
          } else {
            $target_user = get_user_by_id($db, $user_id_to_modify);
            if (!$target_user) {
              $action_error = "User to modify not found.";
            } elseif ($target_user['id'] === $current_user['id']) {
              $action_error = "You cannot modify yourself.";
            } else {
              $current_user_level = $role_hierarchy[$current_user['role']];
              $target_user_level = $role_hierarchy[$target_user['role']];
              if ($current_user_level <= $target_user_level && $current_user['role'] !== ROLE_ADMIN) {
                $action_error = "Permission denied: You cannot modify a user with an equal or higher role.";
              } else {
                $new_status = ($action === 'ban_user') ? STATUS_BANNED : STATUS_ACTIVE;
                $action_verb = ($action === 'ban_user') ? 'banned' : 'unbanned';
                try {
                  $stmt = $db->prepare("UPDATE users SET status = ? WHERE id = ?");
                  $stmt->execute([$new_status, $user_id_to_modify]);
                  $safe_username = urlencode($target_user['username']);
                  header("Location: ./?user_{$action_verb}={$safe_username}");
                  exit;
                } catch (PDOException $e) {
                  $action_error = "Database error updating user status.";
                  error_log("Error {$action_verb} user {$user_id_to_modify}: " . $e->getMessage());
                }
              }
            }
          }
        }
        break;

      case 'delete':
      case 'edit':
      case 'save_edit':
        break;
    }
  }
}

// --- Handle GET Actions (Confirm Delete, Show Edit Form) & POST (Delete, Edit, Save) ---
if (isset($_REQUEST['action']) && !in_array($_REQUEST['action'], ['login', 'register', 'dologin', 'doregister', 'logout', 'ban_user', 'unban_user'])) {
  $action = $_REQUEST['action'];
  $post_type = in_array($_REQUEST['type'] ?? null, ['thread', 'reply']) ? $_REQUEST['type'] : null;
  $post_id = filter_var($_REQUEST['id'] ?? null, FILTER_VALIDATE_INT);
  $submitted_password = $_POST['password'] ?? null;
  $current_user = get_current_user();

  if (!$post_type || !$post_id) {
    $action_error = $action_error ?? "Invalid request parameters.";
  } else {
    try {
      if ($post_type === 'thread') {
        $stmt = $db->prepare("SELECT t.*, u.username as registered_username, u.role as user_role, u.status as user_status
                              FROM threads t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ?");
      } else {
        $stmt = $db->prepare("SELECT r.*, t.channel, u.username as registered_username, u.role as user_role, u.status as user_status
                              FROM replies r JOIN threads t ON r.thread_id = t.id LEFT JOIN users u ON r.user_id = u.id WHERE r.id = ?");
      }
      $stmt->execute([$post_id]);
      $post_data = $stmt->fetch();
    } catch (PDOException $e) {
      error_log("DB Error fetching post for action {$action}: " . $e->getMessage());
      $action_error = $action_error ?? "Database error fetching post.";
    }

    if (!$post_data) {
      $action_error = $action_error ?? ucfirst($post_type) . " not found.";
    } elseif ($action_error === null) {
      $is_own_post = $current_user && isset($post_data['user_id']) && $post_data['user_id'] == $current_user['id'];
      $can_delete_this_post = $is_own_post || user_has_role(ROLE_JANITOR);
      $can_edit_this_post = $is_own_post || user_has_role(ROLE_MODERATOR);
      $post_legacy_username = !$post_data['user_id'] ? ($post_data['username'] ?? null) : null;
      $require_password = $post_legacy_username && !$current_user && !empty($post_data['password_hash']);
      $post_channel = $post_data['channel'] ?? null;
      if (!$post_channel && $post_type === 'reply' && $post_data['thread_id']) {
        try {
          $stmt_chan = $db->prepare("SELECT channel FROM threads WHERE id = ?");
          $stmt_chan->execute([$post_data['thread_id']]);
          $post_channel = $stmt_chan->fetchColumn();
        } catch (PDOException $e) { error_log("Failed to fetch channel for reply {$post_id}: " . $e->getMessage()); }
      }
      $redirect_url_base = $post_channel ? "./?channel=" . urlencode($post_channel) : './';
      $redirect_url_thread = ($post_type === 'reply' && isset($post_data['thread_id'])) ? $redirect_url_base . "&thread=" . $post_data['thread_id'] : $redirect_url_base;

      switch ($action) {
        case 'confirm_delete':
          if (!$can_delete_this_post) { header("Location: ./?access=denied"); exit; }
          $show_action_form = 'delete_confirm';
          $post_data_for_form = ['type' => $post_type, 'id' => $post_id, 'require_password' => $require_password] + $post_data;
          break;

        case 'delete':
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("Location: ./?access=denied"); exit; }
          if (!$can_delete_this_post) { header("Location: ./?access=denied"); exit; }
          $password_ok = !$require_password || verify_legacy_user_password($db, $post_legacy_username, $submitted_password);
          if ($password_ok) {
            try {
              $db->beginTransaction();
              delete_post_file($post_data['image'] ?? null);
              if ($post_type === 'thread') {
                 $stmt_get_reply_images = $db->prepare("SELECT image FROM replies WHERE thread_id = ? AND image IS NOT NULL");
                 $stmt_get_reply_images->execute([$post_id]);
                 while ($reply_image = $stmt_get_reply_images->fetchColumn()) delete_post_file($reply_image);
                $db->prepare("DELETE FROM replies WHERE thread_id = ?")->execute([$post_id]);
                $db->prepare("DELETE FROM threads WHERE id = ?")->execute([$post_id]);
              } else {
                $db->prepare("DELETE FROM replies WHERE id = ?")->execute([$post_id]);
              }
              $db->commit();
              $separator = (strpos($redirect_url_thread, '?') !== false) ? '&' : '?';
              header("Location: " . $redirect_url_thread . $separator . "deleted=" . $post_id); exit;
            } catch (PDOException $e) {
              if ($db->inTransaction()) $db->rollBack();
              error_log("DB Error deleting {$post_type} ID {$post_id}: " . $e->getMessage());
              $action_error = "Database error during deletion.";
            }
          } else {
            $action_error = "Incorrect password for legacy post deletion.";
            $show_action_form = 'delete_confirm';
            $post_data_for_form = ['type' => $post_type, 'id' => $post_id, 'require_password' => true] + $post_data;
          }
          break;

        case 'show_edit_form':
          if (!$can_edit_this_post) { header("Location: ./?access=denied"); exit; }
          if ($require_password) {
            $show_action_form = 'edit_confirm';
          } else {
            $_SESSION['edit_verified'] = ['type' => $post_type, 'id' => $post_id, 'time' => time()];
            $show_action_form = 'edit_fields';
          }
          $post_data_for_form = ['type' => $post_type, 'id' => $post_id] + $post_data;
          break;

        case 'edit':
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("Location: ./?access=denied"); exit; }
          if (!$can_edit_this_post || !$require_password) { header("Location: ./?access=denied"); exit; }
          if (verify_legacy_user_password($db, $post_legacy_username, $submitted_password)) {
            $_SESSION['edit_verified'] = ['type' => $post_type, 'id' => $post_id, 'time' => time()];
            $show_action_form = 'edit_fields';
          } else {
            $action_error = "Incorrect password for legacy post edit.";
            $show_action_form = 'edit_confirm';
          }
          $post_data_for_form = ['type' => $post_type, 'id' => $post_id] + $post_data;
          break;

        case 'save_edit':
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("Location: ./?access=denied"); exit; }
          if (empty($_SESSION['edit_verified']) || $_SESSION['edit_verified']['type'] !== $post_type || $_SESSION['edit_verified']['id'] !== $post_id || (time() - $_SESSION['edit_verified']['time'] > 300)) {
            unset($_SESSION['edit_verified']);
            $action_error = "Edit session invalid or timed out. Please try again.";
          } elseif (!$can_edit_this_post) {
            unset($_SESSION['edit_verified']);
            header("Location: ./?access=denied"); exit;
          } else {
            $new_comment = trim($_POST['comment'] ?? '');
            if (empty($new_comment) || mb_strlen($new_comment) > 4000) {
              $action_error = empty($new_comment) ? "Comment cannot be empty." : "Comment is too long.";
              $show_action_form = 'edit_fields';
              $post_data_for_form = ['type' => $post_type, 'id' => $post_id, 'comment_attempt' => $new_comment] + $post_data;
              if ($post_type === 'thread') $post_data_for_form['subject_attempt'] = trim($_POST['subject'] ?? '');
            } else {
              try {
                if ($post_type === 'thread') {
                  $stmt_update = $db->prepare("UPDATE threads SET subject = ?, comment = ? WHERE id = ?");
                  $stmt_update->execute([trim($_POST['subject'] ?? ''), $new_comment, $post_id]);
                } else {
                  $stmt_update = $db->prepare("UPDATE replies SET comment = ? WHERE id = ?");
                  $stmt_update->execute([$new_comment, $post_id]);
                }
                unset($_SESSION['edit_verified']);
                $separator = (strpos($redirect_url_thread, '?') !== false) ? '&' : '?';
                header("Location: " . $redirect_url_thread . $separator . "edited=" . $post_id . "#post-" . $post_id); exit;
              } catch (PDOException $e) {
                unset($_SESSION['edit_verified']);
                error_log("DB Error updating {$post_type} ID {$post_id}: " . $e->getMessage());
                $action_error = "Database error during update.";
              }
            }
          }
          break;
      }
    }
  }
}

// --- Handle Post Request (New Thread/Reply) ---
$post_error = null;
$post_success = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action']) && !$show_board_index && isset($_POST['comment']) && empty($action_error) && empty($show_action_form) && !$show_login_form && !$show_register_form) {
  $submitted_csrf = $_POST['csrf_token'] ?? null;
  if (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf)) {
    $post_error = "Invalid form submission. Please try again.";
  } else {
    $comment_raw = trim($_POST['comment'] ?? '');
    $thread_id = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT);
    $current_user = get_current_user();
    if (($current_user && $current_user['status'] === STATUS_BANNED) || ($_POST['channel'] ?? '') !== $current_channel_code) {
      $post_error = ($current_user && $current_user['status'] === STATUS_BANNED) ? "Your account is banned." : "Invalid channel for post.";
    }

    $post_user_id = null; $post_username = null; $post_password_hash = null;
    if ($post_error === null) {
      if ($current_user) {
        $post_user_id = $current_user['id'];
      } else {
        $input_username = trim($_POST['username'] ?? '');
        $input_password = $_POST['password'] ?? '';
        if (mb_strlen($input_username) > USERNAME_MAX_LENGTH) {
          $post_error = "Username is too long.";
        } elseif (!empty($input_username)) {
          if (get_user_by_username($db, $input_username)) {
            $post_error = "Username '" . htmlspecialchars($input_username) . "' is registered. Please log in.";
          } else {
            $post_username = $input_username;
            try {
              $stmt_legacy_check = $db->prepare("SELECT password_hash FROM (SELECT password_hash, created_at FROM threads WHERE username = ? COLLATE NOCASE AND password_hash IS NOT NULL AND user_id IS NULL UNION ALL SELECT password_hash, created_at FROM replies WHERE username = ? COLLATE NOCASE AND password_hash IS NOT NULL AND user_id IS NULL) ORDER BY created_at ASC LIMIT 1");
              $stmt_legacy_check->execute([$input_username, $input_username]);
              $legacy_hash_to_verify = $stmt_legacy_check->fetchColumn();
              if ($legacy_hash_to_verify) {
                if (!password_verify($input_password, $legacy_hash_to_verify)) {
                  $post_error = "Invalid password for legacy username '" . htmlspecialchars($input_username) . "'.";
                }
              } else {
                $post_password_hash = null;
              }
            } catch (PDOException $e) { $post_error = "Database error during legacy username check."; }
          }
        }
      }
    }

    if ($post_error === null) {
      $upload_result = handle_upload('image');
      if (isset($upload_result['error'])) {
        $post_error = $upload_result['error'];
      } else {
        $image_path = $upload_result['filename'] ?? null;
        $temp_media_check = process_comment_media_links($comment_raw, 'temp');
        if (empty(trim($temp_media_check['cleaned_text'])) && empty($temp_media_check['media_html']) && !$image_path) {
          $post_error = "A comment, file upload, or media link is required.";
        } elseif (mb_strlen($comment_raw) > 4000) {
          $post_error = "Post content is too long.";
        }
        if ($post_error !== null && $image_path) delete_post_file($image_path);
      }
    }

    if ($post_error === null) {
      try {
        $db->beginTransaction();
        if ($thread_id) {
          $stmt_check_thread = $db->prepare("SELECT 1 FROM threads WHERE id = ? AND channel = ?");
          $stmt_check_thread->execute([$thread_id, $current_channel_code]);
          if (!$stmt_check_thread->fetch()) throw new Exception("Thread not found or channel mismatch.");
          $stmt = $db->prepare("INSERT INTO replies (thread_id, user_id, username, password_hash, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
          $stmt->execute([$thread_id, $post_user_id, $post_username, $post_password_hash, $comment_raw, $upload_result['filename'] ?? null, $upload_result['orig_name'] ?? null, $upload_result['width'] ?? null, $upload_result['height'] ?? null]);
          $new_post_id = $db->lastInsertId();
          $db->prepare("UPDATE threads SET last_reply_at = CURRENT_TIMESTAMP WHERE id = ?")->execute([$thread_id]);
          $db->commit();
          header("Location: ./?channel=" . urlencode($current_channel_code) . "&thread=" . $thread_id . "#post-" . $new_post_id);
          exit;
        } else {
          $stmt = $db->prepare("INSERT INTO threads (channel, user_id, username, password_hash, subject, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
          $stmt->execute([$current_channel_code, $post_user_id, $post_username, $post_password_hash, trim($_POST['subject'] ?? ''), $comment_raw, $upload_result['filename'] ?? null, $upload_result['orig_name'] ?? null, $upload_result['width'] ?? null, $upload_result['height'] ?? null]);
          $new_thread_id = $db->lastInsertId();
          $db->commit();
          header("Location: ./?channel=" . urlencode($current_channel_code) . "&newthread=" . $new_thread_id . "#thread-" . $new_thread_id);
          exit;
        }
      } catch (Exception $e) {
        if ($db->inTransaction()) $db->rollBack();
        error_log("Post Error: " . $e->getMessage());
        $post_error = "Database Error: Could not save post.";
        if (!empty($upload_result['filename'])) delete_post_file($upload_result['filename']);
      }
    }
  }
}

// --- Fetch Data for Display ---
$threads = []; $replies_to_display = []; $reply_counts = [];
$total_threads = 0; $total_pages = 1; $thread_op = null; $current_page = 1;
$board_index_data = []; $users_data = [];
$fetch_page_data = !$show_login_form && !$show_register_form && empty($show_action_form);
if (!empty($action_error) && in_array($show_action_form, ['delete_confirm', 'edit_confirm', 'edit_fields'])) {
  $fetch_page_data = true;
}

if ($fetch_page_data) {
  if ($show_board_index) {
    try {
      $thread_count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
      $reply_count_stmt = $db->prepare("SELECT COUNT(r.id) FROM replies r JOIN threads t ON r.thread_id = t.id WHERE t.channel = ?");
      foreach (ALLOWED_CHANNELS as $channel_code) {
        $thread_count_stmt->execute([$channel_code]); $thread_count = (int)$thread_count_stmt->fetchColumn();
        $reply_count_stmt->execute([$channel_code]); $reply_count = (int)$reply_count_stmt->fetchColumn();
        $board_index_data[$channel_code] = ['code' => $channel_code, 'name' => CHANNEL_NAMES[$channel_code] ?? $channel_code, 'total_posts' => $thread_count + $reply_count];
      }
      $ordered_board_index_data = [];
      foreach ($channel_categories as $category_name => $category_channels) {
        foreach ($category_channels as $channel_code) {
          if (isset($board_index_data[$channel_code])) $ordered_board_index_data[$category_name][$channel_code] = $board_index_data[$channel_code];
        }
      }
      $uncategorized_boards = [];
      foreach (ALLOWED_CHANNELS as $channel_code) {
        $is_categorized = false;
        foreach ($channel_categories as $cat_channels) if (in_array($channel_code, $cat_channels)) { $is_categorized = true; break; }
        if (!$is_categorized && isset($board_index_data[$channel_code])) $uncategorized_boards[$channel_code] = $board_index_data[$channel_code];
      }
      if (!empty($uncategorized_boards)) $ordered_board_index_data['Uncategorized'] = $uncategorized_boards;
    } catch (PDOException $e) { die("Database Fetch Error (Board Index). Please check logs."); }
  } else {
    try {
      $user_ids_to_fetch = [];
      if ($viewing_thread_id) {
        $stmt = $db->prepare("SELECT * FROM threads WHERE id = ? AND channel = ?");
        $stmt->execute([$viewing_thread_id, $current_channel_code]);
        $thread_op = $stmt->fetch();
        if ($thread_op) {
          if (!empty($thread_op['user_id'])) $user_ids_to_fetch[] = $thread_op['user_id'];
          $threads = [$thread_op];
          $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id = ? ORDER BY created_at ASC");
          $replies_stmt->execute([$viewing_thread_id]);
          $all_replies = $replies_stmt->fetchAll();
          $replies_to_display[$viewing_thread_id] = $all_replies;
          $reply_counts[$viewing_thread_id] = count($all_replies);
          foreach ($all_replies as $reply) if (!empty($reply['user_id'])) $user_ids_to_fetch[] = $reply['user_id'];
        } else {
          $action_error = $action_error ?? "Thread not found in this channel.";
          $viewing_thread_id = null;
        }
      }

      if (!$viewing_thread_id) {
        $current_page = max(1, filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT) ?: 1);
        $count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
        $count_stmt->execute([$current_channel_code]);
        $total_threads = (int)$count_stmt->fetchColumn();
        $total_pages = $total_threads > 0 ? max(1, (int)ceil($total_threads / THREADS_PER_PAGE)) : 1;
        $current_page = min($current_page, $total_pages);
        $offset = ($current_page - 1) * THREADS_PER_PAGE;
        $threads_stmt = $db->prepare("SELECT * FROM threads WHERE channel = ? ORDER BY last_reply_at DESC LIMIT ? OFFSET ?");
        $threads_stmt->bindValue(1, $current_channel_code, PDO::PARAM_STR);
        $threads_stmt->bindValue(2, THREADS_PER_PAGE, PDO::PARAM_INT);
        $threads_stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $threads_stmt->execute();
        $threads = $threads_stmt->fetchAll();
        foreach ($threads as $thread) if (!empty($thread['user_id'])) $user_ids_to_fetch[] = $thread['user_id'];
        $threads_on_page_ids = array_column($threads, 'id');
        if (!empty($threads_on_page_ids)) {
          $placeholders = implode(',', array_fill(0, count($threads_on_page_ids), '?'));
          $count_stmt = $db->prepare("SELECT thread_id, COUNT(*) as count FROM replies WHERE thread_id IN ($placeholders) GROUP BY thread_id");
          $count_stmt->execute($threads_on_page_ids);
          $reply_counts_fetched = $count_stmt->fetchAll(PDO::FETCH_KEY_PAIR);
          foreach ($threads_on_page_ids as $tid) $reply_counts[$tid] = (int)($reply_counts_fetched[$tid] ?? 0);
          $all_replies_for_page = [];
          $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id IN ($placeholders) ORDER BY created_at ASC");
          $replies_stmt->execute($threads_on_page_ids);
          while ($reply = $replies_stmt->fetch()) {
            if (!empty($reply['user_id'])) $user_ids_to_fetch[] = $reply['user_id'];
            $all_replies_for_page[$reply['thread_id']][] = $reply;
          }
          foreach ($all_replies_for_page as $tid => $thread_replies) {
            $replies_to_display[$tid] = array_slice($thread_replies, max(0, count($thread_replies) - REPLIES_PREVIEW_COUNT));
          }
          foreach ($threads_on_page_ids as $tid) if (!isset($replies_to_display[$tid])) $replies_to_display[$tid] = [];
        }
      }

      $unique_user_ids = array_unique(array_filter($user_ids_to_fetch));
      if (!empty($unique_user_ids)) {
        $user_placeholders = implode(',', array_fill(0, count($unique_user_ids), '?'));
        $user_stmt = $db->prepare("SELECT id, username, role, status FROM users WHERE id IN ($user_placeholders)");
        $user_stmt->execute(array_values($unique_user_ids));
        while ($user_row = $user_stmt->fetch()) {
          $users_data[$user_row['id']] = $user_row;
        }
      }
    } catch (PDOException $e) {
      error_log("Database Fetch Error (Channel/Thread View): " . $e->getMessage());
      die("A database error occurred while fetching page data.");
    }
  }
}
$current_user = get_current_user();
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/HDBoard.png">
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
        background-color: var(--bg-color); color: var(--text-color); font-family: sans-serif;
        font-size: 10pt; margin: 0; padding: 0;
      }
      .container { max-width: 900px; margin: 15px auto; padding: 0 15px; }
      a { color: var(--link-color); text-decoration: none; }
      a:hover { color: var(--link-hover); text-decoration: underline; }
      header {
        background-color: var(--header-bg); border: 1px solid var(--border-color);
        border-bottom-width: 2px; margin-bottom: 15px; padding: 10px; position: relative;
      }
      header h1 { color: var(--accent-red); margin: 5px 0; font-size: 1.8em; text-align: center; }
      .auth-links { position: absolute; top: 5px; right: 10px; font-size: 0.9em; }
      .auth-links a, .auth-links span { margin-left: 10px; color: var(--link-color); }
      .auth-links a:hover { color: var(--link-hover); }
      .auth-links form { display: inline; }
      .auth-links button {
        background: none; border: none; color: var(--accent-red); cursor: pointer;
        padding: 0; font-size: inherit; text-decoration: underline; margin-left: 10px;
      }
      .auth-links button:hover { color: var(--link-hover); }
      .channel-nav { margin-top: 10px; padding: 10px 0; border-top: 1px dashed var(--border-color); }
      .channel-nav-collapsible {
        border: 1px solid var(--border-color); border-radius: 4px;
        margin-bottom: 10px; background-color: var(--post-bg);
      }
      .channel-nav-collapsible summary {
        padding: 8px 12px; cursor: pointer; font-weight: bold; background-color: var(--summary-bg);
        border-radius: 3px; transition: background-color 0.2s ease; list-style: none; text-align: center;
      }
      .channel-nav-collapsible summary:hover { background-color: var(--summary-hover-bg); }
      .channel-nav-collapsible summary::-webkit-details-marker { display: none; }
      .channel-nav-collapsible summary::before { content: '► '; font-size: 0.8em; margin-right: 5px; }
      .channel-nav-collapsible[open] summary::before { content: '▼ '; }
      .channel-nav-content {
        padding: 10px 15px; display: flex; flex-wrap: wrap; justify-content: center; gap: 5px 10px;
      }
      .channel-nav-category {
        width: 100%; text-align: center; font-weight: bold; color: var(--accent-green);
        margin: 10px 0 5px 0; font-size: 0.9em; border-bottom: 1px dotted var(--border-color); padding-bottom: 3px;
      }
      .channel-nav-category:first-of-type { margin-top: 0; }
      .channel-nav-content a, .board-index-home-link {
        display: inline-block; padding: 4px 8px; border: 1px solid var(--border-color);
        border-radius: 4px; background-color: var(--input-bg); color: var(--link-color);
        font-weight: normal; transition: background-color 0.2s ease, border-color 0.2s ease;
        margin-bottom: 5px; font-size: 0.95em;
      }
      .channel-nav-content a:hover, .board-index-home-link:hover {
        background-color: var(--button-hover-bg); border-color: var(--link-hover);
        color: var(--link-hover); text-decoration: none;
      }
      .channel-nav-content a.active {
        background-color: var(--accent-blue); color: var(--button-text);
        border-color: var(--link-color); font-weight: bold;
      }
      .board-index-home-link.active {
        background-color: var(--accent-red); color: var(--button-text);
        border-color: var(--accent-red); font-weight: bold;
      }
      .nsfw-warning {
        background-color: var(--warning-bg); border: 1px solid var(--warning-border);
        color: var(--warning-text); padding: 10px 30px 10px 10px; margin-bottom: 15px;
        text-align: center; font-weight: bold; position: relative;
      }
      .nsfw-warning-close {
        position: absolute; top: 5px; right: 8px; background: none; border: none; font-size: 1.2em;
        font-weight: bold; color: var(--warning-text); cursor: pointer; padding: 0 5px; line-height: 1;
      }
      .nsfw-warning-close:hover { color: var(--text-color); }
      .post-form, .action-form, .auth-form {
        background-color: var(--form-bg); border: 1px solid var(--border-color);
        padding: 15px; margin-bottom: 20px;
      }
      .action-form { background-color: var(--action-form-bg); }
      .post-form h2, .action-form h2, .action-form h3, .auth-form h2 {
        margin: 0 0 10px 0; color: var(--accent-blue); font-size: 1.2em;
        display: inline-block; vertical-align: middle;
      }
      .action-form h3 { font-size: 1.1em; color: var(--accent-red); }
      .post-form .toggle-button {
        padding: 4px 10px; font-size: 0.9em; cursor: pointer; background-color: var(--button-bg);
        color: var(--button-text); border: 1px solid var(--input-border); border-radius: 3px;
        margin-left: 10px; vertical-align: middle; transition: background-color 0.2s ease;
      }
      .post-form .toggle-button:hover { background-color: var(--button-hover-bg); }
      .post-form-content { margin-top: 10px; padding-top: 10px; border-top: 1px dashed var(--border-color); }
      .reply-form-container {
        background-color: var(--form-bg); border: 1px solid var(--border-color);
        padding: 15px; margin-top: 10px; margin-bottom: 10px;
      }
      .post-form table, .reply-form-container table, .action-form table, .auth-form table {
        border-collapse: collapse; width: 100%;
      }
      .post-form th, .post-form td, .reply-form-container th, .reply-form-container td,
      .action-form th, .action-form td, .auth-form th, .auth-form td {
        padding: 6px; vertical-align: top; text-align: left;
      }
      .post-form th, .reply-form-container th, .action-form th, .auth-form th {
        width: 130px; text-align: right; font-weight: bold;
        color: var(--text-color); padding-right: 10px;
      }
      .reply-form-container th, .action-form th { width: 110px; }
      .auth-form th { width: 150px; }
      .post-form td, .reply-form-container td, .action-form td, .auth-form td { width: auto; }
      .post-form input[type="text"], .post-form input[type="password"], .post-form textarea,
      .reply-form-container input[type="text"], .reply-form-container input[type="password"], .reply-form-container textarea,
      .action-form input[type="text"], .action-form input[type="password"], .action-form textarea,
      .auth-form input[type="text"], .auth-form input[type="password"] {
        width: calc(100% - 16px); padding: 7px; border: 1px solid var(--input-border);
        box-sizing: border-box; font-size: 1em; background-color: var(--input-bg); color: var(--input-text);
      }
      .post-form textarea, .reply-form-container textarea, .action-form textarea { resize: vertical; min-height: 60px; }
      .post-form input[type="file"], .reply-form-container input[type="file"] {
        padding: 5px 0; color: var(--text-color);
      }
      input[type="file"]::file-selector-button {
        background-color: var(--button-bg); color: var(--button-text); border: 1px solid var(--input-border);
        padding: 4px 8px; border-radius: 3px; cursor: pointer; margin-right: 10px;
      }
      input[type="file"]::file-selector-button:hover { background-color: var(--button-hover-bg); }
      .post-form input[type="submit"], .reply-form-container input[type="submit"],
      .action-form input[type="submit"], .auth-form input[type="submit"] {
        padding: 6px 15px; font-weight: bold; cursor: pointer; background-color: var(--button-bg);
        color: var(--button-text); border: 1px solid var(--input-border); border-radius: 3px;
      }
      .post-form input[type="submit"]:hover, .reply-form-container input[type="submit"]:hover,
      .action-form input[type="submit"]:hover, .auth-form input[type="submit"]:hover {
        background-color: var(--button-hover-bg);
      }
      .post-form small, .reply-form-container small, .action-form small, .auth-form small { color: #aaa; font-size: 0.9em; }
      hr { border: 0; border-top: 1px solid var(--border-color); margin: 25px 0; }
      .board-index-category { margin-bottom: 20px; }
      .board-index-category h2 {
        color: var(--accent-green); border-bottom: 1px solid var(--border-color);
        padding-bottom: 5px; margin-bottom: 10px; font-size: 1.3em;
      }
      .board-index-list {
        list-style: none; padding: 0; margin: 0; display: grid;
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px;
      }
      .board-index-list li {
        background-color: var(--board-index-item-bg); border: 1px solid var(--board-index-item-border);
        border-radius: 4px; transition: background-color 0.2s ease;
      }
      .board-index-list li:hover { background-color: var(--board-index-item-hover-bg); }
      .board-index-list a { display: block; padding: 10px 15px; color: var(--link-color); text-decoration: none; }
      .board-index-list a:hover { color: var(--link-hover); text-decoration: none; }
      .board-index-list .board-code { font-weight: bold; color: var(--accent-green); font-size: 1.1em; }
      .board-index-list .board-name { display: block; margin-top: 3px; font-size: 0.95em; color: var(--text-color); }
      .board-index-list .board-post-count {
        display: block; font-size: 0.85em; color: #aaa; margin-top: 5px; text-align: right;
      }
      .thread, .reply {
        background-color: var(--post-bg); border: 1px solid var(--border-color);
        margin-bottom: 10px; padding: 8px 12px; word-wrap: break-word; overflow-wrap: break-word;
      }
      .reply-container { margin-left: 20px; margin-top: 10px; }
      .reply { margin-top: 5px; padding: 6px 10px; max-width: calc(100% - 20px); min-width: 200px; box-sizing: border-box; }
      .post-info { margin-bottom: 3px; font-size: 0.95em; line-height: 1.4; }
      .post-info .subject { color: var(--accent-blue); margin-right: 5px; font-weight: bold; }
      .post-info .name { color: var(--accent-green); font-weight: bold; margin-right: 8px; }
      .post-info .role { font-size: 0.85em; margin-left: 2px; font-weight: normal; vertical-align: middle; }
      .role-user { color: var(--role-user-color); }
      .role-janitor { color: var(--role-janitor-color); font-weight: bold; }
      .role-moderator { color: var(--role-moderator-color); font-weight: bold; }
      .role-admin { color: var(--role-admin-color); font-weight: bold; }
      .status-banned { color: var(--status-banned-color); font-style: italic; text-decoration: line-through; margin-left: 4px; font-weight: bold; }
      .post-info .time, .post-info .post-id { font-size: 0.9em; color: #bbb; font-weight: normal; margin-left: 8px; white-space: nowrap; }
      .post-info .reply-link, .post-info .action-link { font-size: 0.9em; color: #bbb; text-decoration: none; font-weight: normal; margin-left: 8px; white-space: nowrap; }
      .post-info .reply-link a, .post-info .action-link a { color: var(--link-color); }
      .post-info .reply-link a:hover, .post-info .action-link a:hover { color: var(--link-hover); }
      .post-info .action-link a, .post-info .action-link button { color: var(--accent-red); text-decoration: none; }
      .post-info .action-link a:hover, .post-info .action-link button:hover { color: var(--link-hover); text-decoration: underline; }
      .post-info .action-link form { display: inline; margin: 0; padding: 0; }
      .post-info .action-link button {
        background:none; border:none; padding:0; font: inherit; cursor: pointer; margin: 0; vertical-align: baseline;
      }
      .post-info .reply-count { font-size: 0.9em; color: #bbb; font-weight: normal; margin-left: 5px; white-space: nowrap; }
      .file-info {
        font-size: 0.9em; color: #ccc; margin-bottom: 8px; display: flex; align-items: flex-start;
        flex-wrap: wrap; gap: 5px 10px; border-bottom: 1px dashed var(--border-color);
        padding-bottom: 5px; margin-top: 5px;
      }
      .file-info:last-of-type { border-bottom: none; padding-bottom: 0; margin-bottom: 10px; }
      .file-info .media-toggle { flex-shrink: 0; line-height: 1; margin-right: 10px; }
      .file-info .media-toggle button.show-media-btn {
        padding: 4px 8px; cursor: pointer; font-size: 0.9em; background-color: var(--button-bg);
        border: 1px solid var(--input-border); border-radius: 3px; color: var(--button-text);
        line-height: 1.2; white-space: normal; text-align: center; display: inline-block;
      }
      .file-info .media-toggle button.show-media-btn:hover { background-color: var(--button-hover-bg); }
      .file-details { flex-grow: 1; line-height: 1.4; word-break: break-all; min-width: 150px; }
      .file-details a { color: var(--link-color); text-decoration: underline; }
      .file-details a:hover { color: var(--link-hover); }
      .media-container {
        margin-top: 8px; margin-bottom: 10px; border: 1px dashed var(--border-color);
        padding: 5px; display: none; max-width: 100%; box-sizing: border-box;
        overflow: hidden; background-color: var(--bg-color);
      }
      .media-container img, .media-container video, .media-container audio, .media-container iframe {
        display: block; max-width: 100%; height: auto; margin: 0 auto;
      }
      .media-container img { background-color: #000; }
      .media-container video { background-color: #000; }
      .media-container audio { width: 100%; min-height: 30px; }
      .youtube-embed-container, .video-embed-container {
        margin: 5px 0; position: relative; padding-bottom: 56.25%; height: 0;
        overflow: hidden; max-width: 100%; background: #000;
      }
      .youtube-embed-container iframe, .video-embed-container video {
        position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;
      }
      .comment { margin-top: 10px; line-height: 1.5; overflow-wrap: break-word; word-wrap: break-word; word-break: break-word; color: var(--text-color); }
      .comment-truncated { display: block; }
      .comment-full { display: none; }
      .show-full-text-btn {
        display: inline-block; padding: 2px 5px; font-size: 0.8em; cursor: pointer;
        margin-left: 5px; margin-top: 5px; background-color: var(--button-bg);
        border: 1px solid var(--input-border); border-radius: 3px; color: var(--button-text);
      }
      .show-full-text-btn:hover { background-color: var(--button-hover-bg); }
      .greentext { color: var(--greentext-color); }
      .reply-mention { color: var(--reply-mention-color); text-decoration: none; font-weight: bold; }
      .reply-mention:hover { color: var(--link-hover); text-decoration: underline; }
      .omitted-posts { font-size: 0.9em; color: #aaa; margin-left: 20px; margin-top: 5px; margin-bottom: 10px; }
      .omitted-posts a { color: var(--link-color); text-decoration: none; }
      .omitted-posts a:hover { text-decoration: underline; }
      .error, .success {
        font-weight: bold; border: 1px solid; padding: 10px; margin-bottom: 15px; border-radius: 4px; text-align: center;
      }
      .error { color: var(--error-text); background-color: var(--error-bg); border-color: var(--error-border); }
      .success { color: var(--success-text); background-color: var(--success-bg); border-color: var(--success-border); }
      .pagination { text-align: center; margin: 20px 0; font-size: 1.1em; }
      .pagination a, .pagination span {
        display: inline-block; padding: 5px 10px; margin: 0 3px; border: 1px solid var(--border-color);
        background-color: var(--post-bg); text-decoration: none; color: var(--link-color); border-radius: 3px;
      }
      .pagination a:hover { background-color: var(--button-hover-bg); border-color: var(--link-hover); }
      .pagination span.current-page {
        background-color: var(--accent-red); color: var(--button-text); font-weight: bold; border-color: var(--accent-red);
      }
      .pagination span.disabled { color: #888; cursor: not-allowed; background-color: var(--header-bg); border-color: var(--border-color); }
      .thread-view-header {
        background-color: var(--header-bg); border: 1px solid var(--border-color);
        margin-bottom: 15px; padding: 10px; text-align: center; font-size: 1.1em;
        font-weight: bold; color: var(--text-color);
      }
      .thread-view-header a { color: var(--accent-red); }
      .thread-view-header a:hover { color: var(--link-hover); }
      :target { scroll-margin-top: 70px; }
      .post.highlighted, .reply.highlighted {
        background-color: #404050 !important; border-color: var(--link-color) !important;
        transition: background-color 0.3s ease, border-color 0.3s ease;
      }
      #post-form h4, .reply-form-container h4 { margin: 0 0 10px 0; color: var(--accent-blue); }
      .action-form .post-preview {
        background-color: var(--post-bg); border: 1px dashed var(--border-color);
        padding: 10px; margin-bottom: 15px; font-size: 0.9em; max-height: 100px; overflow: auto;
      }
      .flex-container { display: flex; justify-content: center; }
      .flex-container img { max-width: 100%; height: auto; max-height: 250px; margin: 10px auto; display: block; }
      .spoiler {
        background-color: var(--spoiler-bg); color: var(--spoiler-text); padding: 0 3px;
        border-radius: 2px; cursor: help; transition: color 0.2s ease;
      }
      .spoiler:hover { color: var(--spoiler-hover-text); }
      pre.code-block {
        background-color: var(--code-bg); border: 1px solid var(--border-color);
        padding: 10px; margin: 10px 0; overflow-x: auto; white-space: pre-wrap;
        word-wrap: break-word; font-family: monospace; font-size: 0.95em; color: var(--code-text);
      }
      pre.code-block code { font-family: inherit; white-space: inherit; }
      blockquote.quote-block {
        border-left: 3px solid var(--quote-border); background-color: var(--quote-bg);
        padding: 8px 12px; margin: 10px 0 10px 15px; color: var(--text-color);
      }
      blockquote.quote-block cite { display: block; font-style: italic; color: var(--quote-cite); margin-bottom: 5px; font-size: 0.9em; }
      .text-formatter-toolbar {
        margin-bottom: 5px; padding: 3px; background-color: var(--input-bg);
        border: 1px solid var(--input-border); border-bottom: none; border-radius: 3px 3px 0 0;
        display: flex; flex-wrap: wrap; gap: 4px;
      }
      .text-formatter-toolbar button.format-button {
        background-color: var(--button-bg); color: var(--button-text); border: 1px solid var(--input-border);
        padding: 3px 7px; border-radius: 3px; cursor: pointer; font-size: 0.9em;
        font-family: sans-serif; line-height: 1.2; min-width: 25px; text-align: center;
      }
      .text-formatter-toolbar button.format-button:hover { background-color: var(--button-hover-bg); }
      .text-formatter-toolbar + textarea { border-top-left-radius: 0; border-top-right-radius: 0; border-top: 1px solid var(--input-border); }
      @media (max-width: 767px) {
        body { font-size: 11pt; }
        .container { padding: 0 10px; }
        header h1 { font-size: 1.5em; }
        .auth-links { position: static; text-align: center; margin-top: 5px; }
        .channel-nav-content { font-size: 0.9em; gap: 4px 8px; }
        .board-index-list { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
        .post-form th, .reply-form-container th, .action-form th, .auth-form th {
          width: auto; text-align: left; display: block; padding-bottom: 2px; padding-right: 6px;
        }
        .post-form td, .reply-form-container td, .action-form td, .auth-form td { display: block; padding-top: 0; }
        .post-form input[type="text"], .post-form input[type="password"], .post-form textarea,
        .reply-form-container input[type="text"], .reply-form-container input[type="password"], .reply-form-container textarea,
        .action-form input[type="text"], .action-form input[type="password"], .action-form textarea,
        .auth-form input[type="text"], .auth-form input[type="password"] {
          width: calc(100% - 12px); padding: 6px;
        }
        .post-form input[type="submit"], .reply-form-container input[type="submit"],
        .action-form input[type="submit"], .auth-form input[type="submit"] { display: block; width: auto; margin-top: 10px; }
        .file-info { flex-direction: column; align-items: stretch; gap: 5px 0; }
        .file-info .media-toggle { margin-bottom: 5px; margin-right: 0; }
        .file-info .file-details { margin-top: 0; font-size: 1em; min-width: 0; }
        .reply-container { margin-left: 0; }
        .reply, .omitted-posts, .reply-form-container { margin-left: 5px; margin-right: 5px; max-width: calc(100% - 10px); min-width: auto; }
        .post-info { font-size: 0.9em; line-height: 1.5; }
        .post-info .name { display: inline; margin-bottom: 0; }
        .post-info .time, .post-info .post-id, .post-info .reply-link,
        .post-info .action-link, .post-info .reply-count {
          font-size: 0.9em; margin-left: 4px; display: inline;
          margin-bottom: 3px; margin-right: 5px; white-space: normal;
        }
        .post-info .time:first-of-type { margin-left: 0; }
        .pagination { font-size: 1em; }
        .pagination a, .pagination span { padding: 3px 6px; }
        .thread-view-header { font-size: 1em; }
        :target { scroll-margin-top: 60px; }
      }
      @media (min-width: 768px) {
        .auth-links { position: absolute; top: 5px; right: 10px; }
        .post-form th, .action-form th, .auth-form th { width: 130px; text-align: right; display: table-cell; }
        .post-form td, .action-form td, .auth-form td { display: table-cell; }
        .reply-form-container th { width: 110px; }
        .auth-form th { width: 150px; }
        .file-info { flex-direction: row; align-items: flex-start; gap: 5px 10px; }
        .file-info .media-toggle { margin-bottom: 0; margin-right: 10px; }
        .file-info .file-details { margin-top: 0; }
        .reply-container { margin-left: 20px; }
        .reply, .omitted-posts, .reply-form-container { margin-left: 20px; margin-right: 0; max-width: calc(100% - 20px); }
        .post-info .name { display: inline-block; margin-bottom: 0; }
        .post-info .time, .post-info .post-id, .post-info .reply-link,
        .post-info .action-link, .post-info .reply-count {
          font-size: 0.9em; margin-left: 8px; display: inline;
          margin-bottom: 0; margin-right: 0; white-space: nowrap;
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
      const UPLOADS_URL_PATH = <?php echo json_encode(UPLOADS_URL_PATH); ?>;
    </script>
    <script>
      function insertBbCode(textareaId, tag) {
        const textarea = document.getElementById(textareaId);
        if (!textarea) return;
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const sel = textarea.value.substring(start, end);
        let replacement;
        let cursor_pos = start;
        const simpleTags = ['b', 'i', 'u', 's', 'spoiler'];
        const blockTags = ['quote', 'code'];
        if (simpleTags.includes(tag)) {
          replacement = sel ? `[${tag}]${sel}[/${tag}]` : `[${tag}][/${tag}]`;
          cursor_pos = sel ? start + replacement.length : start + `[${tag}]`.length;
        } else if (blockTags.includes(tag)) {
          replacement = sel ? `[${tag}]\n${sel.trim()}\n[/${tag}]` : `\n[${tag}]\n\n[/${tag}]\n`;
          cursor_pos = sel ? start + replacement.length : start + `\n[${tag}]\n`.length;
          if (start > 0 && textarea.value.substring(start - 1, start) !== '\n') {
            replacement = '\n' + replacement;
            cursor_pos++;
          }
        }
        textarea.value = textarea.value.substring(0, start) + replacement + textarea.value.substring(end);
        textarea.focus();
        textarea.selectionStart = textarea.selectionEnd = cursor_pos;
      }

      function toggleMedia(button) {
        const fileInfoDiv = button.closest('.file-info');
        const mediaContainer = fileInfoDiv?.nextElementSibling;
        if (!mediaContainer || !mediaContainer.classList.contains('media-container')) return;
        const { mediaUrl, mediaType } = button.dataset;
        const isHidden = mediaContainer.style.display === 'none';
        const textMap = {
          image: ['View Image', 'Hide Image'], video: ['View Video', 'Hide Video'],
          audio: ['View Audio', 'Hide Audio'], youtube: ['View YouTube', 'Hide YouTube']
        };
        const [viewText, hideText] = textMap[mediaType] || ['View Media', 'Hide Media'];
        if (isHidden) {
          mediaContainer.style.display = 'block';
          button.textContent = hideText;
          if (mediaContainer.dataset.loadedUrl !== mediaUrl) {
            mediaContainer.innerHTML = '<span>Loading...</span>';
            mediaContainer.dataset.loadedUrl = mediaUrl;
            let mediaElement;
            if (mediaType === 'image') {
              const link = document.createElement('a');
              link.href = mediaUrl; link.target = '_blank';
              mediaElement = document.createElement('img');
              mediaElement.src = mediaUrl;
              link.appendChild(mediaElement);
              mediaContainer.innerHTML = '';
              mediaContainer.appendChild(link);
            } else if (mediaType === 'video' || mediaType === 'audio') {
              mediaElement = document.createElement(mediaType);
              mediaElement.src = mediaUrl; mediaElement.controls = true;
              mediaContainer.innerHTML = '';
              mediaContainer.appendChild(mediaElement);
            } else if (mediaType === 'youtube') {
              const videoId = (mediaUrl.match(/(?:v=|embed\/|be\/|shorts\/)([a-zA-Z0-9_-]{11})/) || [])[1];
              if (videoId) {
                const embedContainer = document.createElement('div');
                embedContainer.className = 'youtube-embed-container';
                mediaElement = document.createElement('iframe');
                mediaElement.src = `https://www.youtube.com/embed/${videoId}`;
                mediaElement.setAttribute('allowfullscreen', '');
                embedContainer.appendChild(mediaElement);
                mediaContainer.innerHTML = '';
                mediaContainer.appendChild(embedContainer);
              } else { mediaContainer.innerHTML = '<span class="error">Invalid YouTube URL</span>'; }
            }
            if (mediaElement) mediaElement.onerror = () => { mediaContainer.innerHTML = '<span class="error">Failed to load media.</span>'; };
          }
        } else {
          mediaContainer.style.display = 'none';
          button.textContent = viewText;
          mediaContainer.querySelectorAll('video, audio, iframe').forEach(el => {
            if (typeof el.pause === 'function') el.pause();
            el.src = 'about:blank';
          });
          mediaContainer.innerHTML = '';
          delete mediaContainer.dataset.loadedUrl;
        }
      }

      function toggleFullText(button) {
        const truncatedDiv = button.closest('.comment-truncated');
        const fullDiv = document.getElementById(button.dataset.targetId);
        if (truncatedDiv && fullDiv) {
          truncatedDiv.style.display = 'none';
          fullDiv.style.display = 'block';
        }
      }

      function toggleReplyForm(threadId) {
        const form = document.getElementById(`reply-form-${threadId}`);
        if (form) {
          const isHidden = form.style.display === 'none';
          form.style.display = isHidden ? 'block' : 'none';
          if (isHidden) {
            form.scrollIntoView({ behavior: 'smooth', block: 'center' });
            form.querySelector('textarea[name="comment"]')?.focus();
          }
        }
      }

      document.addEventListener('DOMContentLoaded', function() {
        let highlightTimeout = null;
        const highlightPost = (targetPost) => {
          if (!targetPost) return;
          clearTimeout(highlightTimeout);
          document.querySelectorAll('.highlighted').forEach(el => el.classList.remove('highlighted'));
          targetPost.classList.add('highlighted');
          highlightTimeout = setTimeout(() => targetPost.classList.remove('highlighted'), 2500);
        };
        document.body.addEventListener('click', function(event) {
          const target = event.target;
          if (target.matches('.show-media-btn')) toggleMedia(target);
          if (target.matches('.show-full-text-btn')) toggleFullText(target);
          if (target.matches('#nsfw-warning-close')) {
            const warning = document.getElementById('nsfw-warning');
            if (warning) {
              warning.style.display = 'none';
              try { localStorage.setItem('hideNsfwWarning_' + currentChannel, 'true'); } catch (e) {}
            }
          }
          const replyLink = target.closest('a[href^="#reply-form-"]');
          if (replyLink) {
            event.preventDefault();
            const threadId = replyLink.href.split('-').pop();
            toggleReplyForm(threadId);
          }
          const mentionLink = target.closest('.reply-mention');
          if (mentionLink) {
            const targetPost = document.getElementById(mentionLink.hash.substring(1))?.closest('.post, .reply');
            highlightPost(targetPost);
          }
        });

        document.body.addEventListener('mouseover', e => {
          const link = e.target.closest('.reply-mention');
          if (link) {
            const targetPost = document.getElementById(link.hash.substring(1))?.closest('.post, .reply');
            if (targetPost && !targetPost.classList.contains('highlighted')) targetPost.classList.add('highlighted');
          }
        });
        document.body.addEventListener('mouseout', e => {
          const link = e.target.closest('.reply-mention');
          if (link) {
            const targetPost = document.getElementById(link.hash.substring(1))?.closest('.post, .reply');
            if (targetPost && !setTimeout(() => {}, 0)) targetPost.classList.remove('highlighted');
          }
        });

        if (window.location.hash?.startsWith('#post-')) {
          requestAnimationFrame(() => highlightPost(document.getElementById(window.location.hash.substring(1))?.closest('.post, .reply')));
        }
        const postFormContent = document.getElementById('postFormContent');
        const toggleButton = document.getElementById('togglePostFormButton');
        if (toggleButton && postFormContent && currentChannel) {
          const stateKey = 'postFormState_channel_' + currentChannel;
          let savedState = 'collapsed';
          try { savedState = localStorage.getItem(stateKey) || 'collapsed'; } catch (e) {}
          postFormContent.style.display = savedState === 'expanded' ? 'block' : 'none';
          toggleButton.textContent = savedState === 'expanded' ? 'Hide Form' : 'Show Form';
          toggleButton.addEventListener('click', () => {
            const isCollapsed = postFormContent.style.display === 'none';
            postFormContent.style.display = isCollapsed ? 'block' : 'none';
            toggleButton.textContent = isCollapsed ? 'Hide Form' : 'Show Form';
            try { localStorage.setItem(stateKey, isCollapsed ? 'expanded' : 'collapsed'); } catch (e) {}
          });
        }
        if (currentChannel) {
          const nsfwWarning = document.getElementById('nsfw-warning');
          try {
            if (nsfwWarning && localStorage.getItem('hideNsfwWarning_' + currentChannel) === 'true') {
              nsfwWarning.style.display = 'none';
            }
          } catch(e){}
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
            <a href="./" class="<?php echo $show_board_index ? 'board-index-home-link active' : 'board-index-home-link'; ?>">Home</a>
            <?php foreach ($channel_categories as $category_name => $category_channels) : ?>
              <span class="channel-nav-category"><?php echo htmlspecialchars($category_name); ?></span>
              <?php foreach ($category_channels as $channel_code_nav) : if (isset(CHANNEL_NAMES[$channel_code_nav])) : ?>
                <a href="./?channel=<?php echo urlencode($channel_code_nav); ?>" class="<?php echo (!$show_board_index && isset($current_channel_code) && $channel_code_nav === $current_channel_code) ? 'active' : ''; ?>"><?php echo htmlspecialchars(CHANNEL_NAMES[$channel_code_nav]); ?></a>
              <?php endif; endforeach; ?>
            <?php endforeach; ?>
            <?php
              $all_categorized_flat = empty($channel_categories) ? [] : array_merge(...array_values($channel_categories));
              $uncategorized = array_diff(ALLOWED_CHANNELS, $all_categorized_flat);
            ?>
            <?php if (!empty($uncategorized)) : ?>
              <span class="channel-nav-category">Uncategorized</span>
              <?php foreach ($uncategorized as $channel_code_nav) : if (isset(CHANNEL_NAMES[$channel_code_nav])) : ?>
                <a href="./?channel=<?php echo urlencode($channel_code_nav); ?>" class="<?php echo (!$show_board_index && isset($current_channel_code) && $channel_code_nav === $current_channel_code) ? 'active' : ''; ?>"><?php echo htmlspecialchars(CHANNEL_NAMES[$channel_code_nav]); ?></a>
              <?php endif; endforeach; ?>
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
      <?php if (isset($_GET['user_banned'])): ?><p class="success">User '<?php echo htmlspecialchars($_GET['user_banned']); ?>' has been banned.</p><?php endif; ?>
      <?php if (isset($_GET['user_unbanned'])): ?><p class="success">User '<?php echo htmlspecialchars($_GET['user_unbanned']); ?>' has been unbanned.</p><?php endif; ?>
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
              <tr><th><label for="reg_username">Username</label></th><td><input type="text" name="username" id="reg_username" required maxlength="<?php echo USERNAME_MAX_LENGTH; ?>" pattern="[a-zA-Z0-9_]+"> <small>(Letters, numbers, _)</small></td></tr>
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
          $form_username = !empty($post_data_for_form['user_id']) && isset($users_data[$post_data_for_form['user_id']])
            ? $users_data[$post_data_for_form['user_id']]['username']
            : ($post_data_for_form['username'] ?? 'Anonymous');
          $form_comment_preview = htmlspecialchars(mb_substr(strip_tags($post_data_for_form['comment'] ?? ''), 0, 150)) . '...';
          $form_require_password = $post_data_for_form['require_password'] ?? false;
        ?>
        <?php if ($form_post_type && $form_post_id): ?>
          <div class="action-form">
            <?php if ($show_action_form === 'delete_confirm'): ?>
              <h3>Confirm Deletion</h3>
              <p>Are you sure you want to delete this <?php echo htmlspecialchars($form_post_type); ?> (ID: <?php echo $form_post_id; ?>)?</p>
              <div class="post-preview"><strong>Comment:</strong> <?php echo $form_comment_preview; ?></div>
              <form action="./" method="post">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <?php if ($form_require_password): ?>
                  <tr><th><label for="password_del">Password</label></th><td><input type="password" name="password" id="password_del" required> <small>for legacy user '<?php echo htmlspecialchars($form_username); ?>'</small></td></tr>
                  <?php endif; ?>
                  <tr><th></th><td><input type="submit" value="Confirm Delete"></td></tr>
                </table>
              </form>

            <?php elseif ($show_action_form === 'edit_confirm'): ?>
              <h3>Verify Ownership to Edit</h3>
              <p>Please enter the password for legacy user '<strong><?php echo htmlspecialchars($form_username); ?></strong>' to edit this <?php echo htmlspecialchars($form_post_type); ?>.</p>
              <form action="./" method="post">
                <input type="hidden" name="action" value="edit">
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
              <form action="./" method="post">
                <input type="hidden" name="action" value="save_edit">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <?php if ($form_post_type === 'thread'): ?>
                  <tr><th><label for="subject_edit">Subject</label></th><td><input type="text" name="subject" id="subject_edit" value="<?php echo htmlspecialchars($post_data_for_form['subject_attempt'] ?? $post_data_for_form['subject'] ?? ''); ?>"></td></tr>
                  <?php endif; ?>
                  <tr>
                    <th><label for="comment_edit">Comment</label></th>
                    <td>
                      <?php $edit_textarea_id = 'comment_edit'; ?>
                      <div class="text-formatter-toolbar">
                        <button type="button" class="format-button" onclick="insertBbCode('<?php echo $edit_textarea_id; ?>', 'b')"><b>B</b></button>
                        <button type="button" class="format-button" onclick="insertBbCode('<?php echo $edit_textarea_id; ?>', 'i')"><i>I</i></button>
                        <button type="button" class="format-button" onclick="insertBbCode('<?php echo $edit_textarea_id; ?>', 's')"><del>S</del></button>
                        <button type="button" class="format-button" onclick="insertBbCode('<?php echo $edit_textarea_id; ?>', 'spoiler')">Spoiler</button>
                        <button type="button" class="format-button" onclick="insertBbCode('<?php echo $edit_textarea_id; ?>', 'code')">Code</button>
                        <button type="button" class="format-button" onclick="insertBbCode('<?php echo $edit_textarea_id; ?>', 'quote')">Quote</button>
                      </div>
                      <textarea name="comment" id="<?php echo $edit_textarea_id; ?>" rows="5" required><?php echo htmlspecialchars($post_data_for_form['comment_attempt'] ?? $post_data_for_form['comment'] ?? ''); ?></textarea>
                    </td>
                  </tr>
                  <tr><th></th><td><input type="submit" value="Save Changes"></td></tr>
                </table>
              </form>
            <?php endif; ?>
          </div>
          <hr>
        <?php endif; ?>
      <?php endif; ?>

      <?php // --- Main Content Display --- ?>
      <?php if ($fetch_page_data): ?>
        <?php if ($show_board_index): ?>
          <?php if (!empty($ordered_board_index_data)): ?>
            <?php foreach ($ordered_board_index_data as $category_name => $boards_in_category): ?>
              <div class="board-index-category">
                <h2><?php echo htmlspecialchars($category_name); ?></h2>
                <ul class="board-index-list">
                  <?php foreach ($boards_in_category as $board): ?>
                  <li>
                    <a href="./?channel=<?php echo urlencode($board['code']); ?>">
                      <span class="board-code">/<?php echo htmlspecialchars($board['code']); ?>/</span>
                      <span class="board-name"><?php echo htmlspecialchars($board['name']); ?></span>
                      <span class="board-post-count">(<?php echo number_format($board['total_posts']); ?> posts)</span>
                    </a>
                  </li>
                  <?php endforeach; ?>
                </ul>
              </div>
            <?php endforeach; ?>
          <?php else: ?>
            <p style="text-align: center; color: #aaa;">No boards found.</p>
          <?php endif; ?>

        <?php elseif ($current_channel_code): ?>
          <?php if (!$viewing_thread_id && in_array($current_channel_code, NSFW_CHANNELS)) : ?>
            <div class="nsfw-warning" id="nsfw-warning">
              <strong>Warning:</strong> Content on /<?php echo htmlspecialchars($current_channel_code); ?>/ may be NSFW.
              <button class="nsfw-warning-close" id="nsfw-warning-close" title="Close Warning">×</button>
            </div>
          <?php endif; ?>

          <?php if ($viewing_thread_id && $thread_op): ?>
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
                    <tr><th><label for="reply_username">Username</label></th><td><input type="text" name="username" id="reply_username" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td></tr>
                    <tr><th><label for="reply_password">Password</label></th><td><input type="password" name="password" id="reply_password"> <small>(For legacy user)</small></td></tr>
                    <?php endif; ?>
                    <tr>
                      <th><label for="reply_comment">Comment</label></th>
                      <td>
                        <?php $reply_textarea_id = 'reply_comment'; ?>
                        <div class="text-formatter-toolbar">
                          <button type="button" class="format-button" onclick="insertBbCode('<?php echo $reply_textarea_id; ?>', 'b')"><b>B</b></button>
                          <button type="button" class="format-button" onclick="insertBbCode('<?php echo $reply_textarea_id; ?>', 'i')"><i>I</i></button>
                          <button type="button" class="format-button" onclick="insertBbCode('<?php echo $reply_textarea_id; ?>', 's')"><del>S</del></button>
                          <button type="button" class="format-button" onclick="insertBbCode('<?php echo $reply_textarea_id; ?>', 'spoiler')">Spoiler</button>
                          <button type="button" class="format-button" onclick="insertBbCode('<?php echo $reply_textarea_id; ?>', 'code')">Code</button>
                          <button type="button" class="format-button" onclick="insertBbCode('<?php echo $reply_textarea_id; ?>', 'quote')">Quote</button>
                        </div>
                        <textarea name="comment" id="<?php echo $reply_textarea_id; ?>" rows="4" required></textarea>
                      </td>
                    </tr>
                    <tr><th><label for="reply_image">File</label></th><td><input type="file" name="image" id="reply_image"></td></tr>
                    <tr><th></th><td><input type="submit" value="Submit Reply"></td></tr>
                  </table>
                </form>
              </div>
            <?php elseif ($current_user && $current_user['status'] === STATUS_BANNED): ?>
              <p class="error">You are banned and cannot reply.</p>
            <?php endif; ?>
            <hr>
            <?php
              $thread = $threads[0];
              $thread_id = $thread['id'];
              $post_element_id_prefix = 'post-' . $thread_id;
              $op_user_info = (!empty($thread['user_id']) && isset($users_data[$thread['user_id']])) ? $users_data[$thread['user_id']] : null;
              $op_display_name = $op_user_info ? htmlspecialchars($op_user_info['username']) : ($thread['username'] ? htmlspecialchars($thread['username']) : 'Anonymous');
              $op_display_role = $op_user_info ? $op_user_info['role'] : null;
              $op_display_status = $op_user_info ? $op_user_info['status'] : null;
              $op_is_legacy_anon = !$op_user_info && !empty($thread['username']) && !empty($thread['password_hash']);
              $can_edit_op = ($current_user && $op_user_info && $current_user['id'] === $op_user_info['id']) || user_has_role(ROLE_MODERATOR);
              $can_delete_op = ($current_user && $op_user_info && $current_user['id'] === $op_user_info['id']) || user_has_role(ROLE_JANITOR);
              $show_ban_button_for_op = $current_user && $op_user_info && $op_user_info['id'] !== $current_user['id'] && user_has_role(ROLE_JANITOR) && ($role_hierarchy[$current_user['role']] > $role_hierarchy[$op_user_info['role']] || $current_user['role'] === ROLE_ADMIN);
              $uploaded_media_html = generate_uploaded_media_html($thread, $post_element_id_prefix);
              $link_media_result = process_comment_media_links($thread['comment'], $post_element_id_prefix);
              $linked_media_html = $link_media_result['media_html'];
              $formatted_comment = format_comment($link_media_result['cleaned_text']);
            ?>
            <div class="thread" id="thread-<?php echo $thread_id; ?>">
              <div class="post op" id="<?php echo $post_element_id_prefix; ?>">
                <p class="post-info">
                  <?php if (!empty($thread['subject'])): ?><span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span><?php endif; ?>
                  <span class="name"><?php echo $op_display_name; ?></span>
                  <?php if ($op_display_role): ?><span class="role role-<?php echo htmlspecialchars($op_display_role); ?>">(<?php echo ucfirst(htmlspecialchars($op_display_role)); ?>)</span><?php endif; ?>
                  <?php if ($op_display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                  <?php if ($op_is_legacy_anon): ?><span class="role">(Legacy)</span><?php endif; ?>
                  <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                  <span class="post-id">No.<?php echo $thread_id; ?></span>
                  <a href="#<?php echo $post_element_id_prefix; ?>" class="reply-link" title="Link to post">▶</a>
                  <?php if ($can_edit_op): ?><span class="action-link">[<a href="./?action=show_edit_form&type=thread&id=<?php echo $thread_id; ?>">Edit</a>]</span><?php endif; ?>
                  <?php if ($can_delete_op): ?><span class="action-link">[<a href="./?action=confirm_delete&type=thread&id=<?php echo $thread_id; ?>">Delete</a>]</span><?php endif; ?>
                  <?php if ($show_ban_button_for_op): ?>
                    <span class="action-link">
                      <form action="./" method="post" style="display: inline;">
                        <input type="hidden" name="action" value="<?php echo ($op_display_status === STATUS_BANNED ? 'unban_user' : 'ban_user'); ?>">
                        <input type="hidden" name="user_id" value="<?php echo $op_user_info['id']; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <button type="submit">[<?php echo ($op_display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?>]</button>
                      </form>
                    </span>
                  <?php endif; ?>
                </p>
                <?php echo $uploaded_media_html; ?><?php echo $linked_media_html; ?>
                <div class="comment"><?php echo $formatted_comment; ?></div>
              </div>

              <div class="reply-container">
                <?php foreach ($replies_to_display[$thread_id] ?? [] as $reply): ?>
                  <?php
                    $reply_id = $reply['id'];
                    $reply_element_id_prefix = 'post-' . $reply_id;
                    $reply_user_info = (!empty($reply['user_id']) && isset($users_data[$reply['user_id']])) ? $users_data[$reply['user_id']] : null;
                    $reply_display_name = $reply_user_info ? htmlspecialchars($reply_user_info['username']) : ($reply['username'] ? htmlspecialchars($reply['username']) : 'Anonymous');
                    $reply_display_role = $reply_user_info ? $reply_user_info['role'] : null;
                    $reply_display_status = $reply_user_info ? $reply_user_info['status'] : null;
                    $reply_is_legacy_anon = !$reply_user_info && !empty($reply['username']) && !empty($reply['password_hash']);
                    $can_edit_reply = ($current_user && $reply_user_info && $current_user['id'] === $reply_user_info['id']) || user_has_role(ROLE_MODERATOR);
                    $can_delete_reply = ($current_user && $reply_user_info && $current_user['id'] === $reply_user_info['id']) || user_has_role(ROLE_JANITOR);
                    $show_ban_button_for_reply = $current_user && $reply_user_info && $reply_user_info['id'] !== $current_user['id'] && user_has_role(ROLE_JANITOR) && ($role_hierarchy[$current_user['role']] > $role_hierarchy[$reply_user_info['role']] || $current_user['role'] === ROLE_ADMIN);
                    $reply_uploaded_media_html = generate_uploaded_media_html($reply, $reply_element_id_prefix);
                    $reply_link_media_result = process_comment_media_links($reply['comment'], $reply_element_id_prefix);
                    $reply_linked_media_html = $reply_link_media_result['media_html'];
                    $reply_formatted_comment = format_comment($reply_link_media_result['cleaned_text']);
                  ?>
                  <div class="reply" id="<?php echo $reply_element_id_prefix; ?>">
                    <p class="post-info">
                      <span class="name"><?php echo $reply_display_name; ?></span>
                      <?php if ($reply_display_role): ?><span class="role role-<?php echo htmlspecialchars($reply_display_role); ?>">(<?php echo ucfirst(htmlspecialchars($reply_display_role)); ?>)</span><?php endif; ?>
                      <?php if ($reply_display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                      <?php if ($reply_is_legacy_anon): ?><span class="role">(Legacy)</span><?php endif; ?>
                      <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                      <span class="post-id">No.<?php echo $reply_id; ?></span>
                      <a href="#<?php echo $reply_element_id_prefix; ?>" class="reply-link" title="Link to post">▶</a>
                      <?php if ($can_edit_reply): ?><span class="action-link">[<a href="./?action=show_edit_form&type=reply&id=<?php echo $reply_id; ?>">Edit</a>]</span><?php endif; ?>
                      <?php if ($can_delete_reply): ?><span class="action-link">[<a href="./?action=confirm_delete&type=reply&id=<?php echo $reply_id; ?>">Delete</a>]</span><?php endif; ?>
                      <?php if ($show_ban_button_for_reply): ?>
                        <span class="action-link">
                          <form action="./" method="post" style="display: inline;">
                            <input type="hidden" name="action" value="<?php echo ($reply_display_status === STATUS_BANNED ? 'unban_user' : 'ban_user'); ?>">
                            <input type="hidden" name="user_id" value="<?php echo $reply_user_info['id']; ?>">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit">[<?php echo ($reply_display_status === STATUS_BANNED ? 'Unban' : 'Ban'); ?>]</button>
                          </form>
                        </span>
                      <?php endif; ?>
                    </p>
                    <?php echo $reply_uploaded_media_html; ?><?php echo $reply_linked_media_html; ?>
                    <div class="comment"><?php echo $reply_formatted_comment; ?></div>
                  </div>
                <?php endforeach; ?>
                <?php if (empty($replies_to_display[$thread_id] ?? [])): ?>
                  <p style="text-align: center; color: #aaa; margin-top: 15px;">No replies yet.</p>
                <?php endif; ?>
              </div>
            </div>
            <hr>

          <?php else: ?>
            <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?>
              <div class="post-form" id="post-form">
                <h2>Post new thread in /<?php echo htmlspecialchars($current_channel_code); ?>/ <button id="togglePostFormButton" class="toggle-button" type="button">Show Form</button></h2>
                <div id="postFormContent" class="post-form-content" style="display: none;">
                  <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                    <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <table>
                      <?php if (!$current_user): ?>
                      <tr><th><label for="username">Username</label></th><td><input type="text" name="username" id="username" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td></tr>
                      <tr><th><label for="password">Password</label></th><td><input type="password" name="password" id="password"> <small>(For legacy user)</small></td></tr>
                      <?php endif; ?>
                      <tr><th><label for="subject">Subject</label></th><td><input type="text" name="subject" id="subject"></td></tr>
                      <tr>
                        <th><label for="comment">Comment</label></th>
                        <td>
                          <?php $main_textarea_id = 'comment'; ?>
                          <div class="text-formatter-toolbar">
                            <button type="button" class="format-button" onclick="insertBbCode('<?php echo $main_textarea_id; ?>', 'b')"><b>B</b></button>
                            <button type="button" class="format-button" onclick="insertBbCode('<?php echo $main_textarea_id; ?>', 'i')"><i>I</i></button>
                            <button type="button" class="format-button" onclick="insertBbCode('<?php echo $main_textarea_id; ?>', 's')"><del>S</del></button>
                            <button type="button" class="format-button" onclick="insertBbCode('<?php echo $main_textarea_id; ?>', 'spoiler')">Spoiler</button>
                            <button type="button" class="format-button" onclick="insertBbCode('<?php echo $main_textarea_id; ?>', 'code')">Code</button>
                            <button type="button" class="format-button" onclick="insertBbCode('<?php echo $main_textarea_id; ?>', 'quote')">Quote</button>
                          </div>
                          <textarea name="comment" id="<?php echo $main_textarea_id; ?>" rows="5"></textarea>
                        </td>
                      </tr>
                      <tr><th><label for="image">File</label></th><td><input type="file" name="image" id="image"></td></tr>
                      <tr><th></th><td><input type="submit" value="Submit Thread"></td></tr>
                    </table>
                  </form>
                </div>
              </div>
            <?php elseif ($current_user && $current_user['status'] === STATUS_BANNED): ?>
              <p class="error">You are banned and cannot post new threads.</p>
            <?php endif; ?>
            <hr>
            <?php if ($total_threads == 0 && !$viewing_thread_id): ?>
              <p style="text-align: center; color: #aaa; margin-top: 30px;">No threads in /<?php echo htmlspecialchars($current_channel_code); ?>/ yet.</p>
            <?php elseif ($total_threads > 0 || $viewing_thread_id): ?>
              <?php if (!$viewing_thread_id): ?>
                <div class="pagination">
                  <?php if ($current_page > 1) : ?><a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a><?php else : ?><span class="disabled"><< Prev</span><?php endif; ?>
                  <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
                  <?php if ($current_page < $total_pages) : ?><a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a><?php else : ?><span class="disabled">Next >></span><?php endif; ?>
                </div>
                <hr>
              <?php endif; ?>
              <?php foreach ($threads as $thread): ?>
                <?php
                  $thread_id = $thread['id'];
                  $post_element_id_prefix = 'post-' . $thread_id;
                  $total_reply_count = $reply_counts[$thread_id] ?? 0;
                  $thread_replies_preview = $replies_to_display[$thread_id] ?? [];
                  $omitted_count = max(0, $total_reply_count - count($thread_replies_preview));
                  $op_user_info = (!empty($thread['user_id']) && isset($users_data[$thread['user_id']])) ? $users_data[$thread['user_id']] : null;
                  $op_display_name = $op_user_info ? htmlspecialchars($op_user_info['username']) : ($thread['username'] ? htmlspecialchars($thread['username']) : 'Anonymous');
                  $op_display_role = $op_user_info ? $op_user_info['role'] : null;
                  $op_display_status = $op_user_info ? $op_user_info['status'] : null;
                  $op_is_legacy_anon = !$op_user_info && !empty($thread['username']) && !empty($thread['password_hash']);
                  $can_edit_op = ($current_user && $op_user_info && $current_user['id'] === $op_user_info['id']) || user_has_role(ROLE_MODERATOR);
                  $can_delete_op = ($current_user && $op_user_info && $current_user['id'] === $op_user_info['id']) || user_has_role(ROLE_JANITOR);
                  $show_ban_button_for_op = $current_user && $op_user_info && $op_user_info['id'] !== $current_user['id'] && user_has_role(ROLE_JANITOR) && ($role_hierarchy[$current_user['role']] > $role_hierarchy[$op_user_info['role']] || $current_user['role'] === ROLE_ADMIN);
                  $uploaded_media_html = generate_uploaded_media_html($thread, $post_element_id_prefix);
                  $link_media_result = process_comment_media_links($thread['comment'], $post_element_id_prefix);
                  $cleaned_comment = $link_media_result['cleaned_text'];
                  $linked_media_html = $link_media_result['media_html'];
                  $display_comment_html = '';
                  if (mb_strlen($thread['comment']) > COMMENT_PREVIEW_LENGTH) {
                     $preview_text = mb_substr($cleaned_comment, 0, COMMENT_PREVIEW_LENGTH) . '...';
                     $full_comment_id = 'full-comment-' . $post_element_id_prefix;
                     $display_comment_html = "<div class='comment-truncated'>" . format_comment($preview_text) . " <br><button class='show-full-text-btn' data-target-id='{$full_comment_id}'>View Full Text</button></div><div id='{$full_comment_id}' class='comment-full'>" . format_comment($cleaned_comment) . "</div>";
                  } else {
                     $display_comment_html = format_comment($cleaned_comment);
                  }
                ?>
                <div class="thread" id="thread-<?php echo $thread_id; ?>">
                  <div class="post op" id="<?php echo $post_element_id_prefix; ?>">
                    <p class="post-info">
                      <?php if (!empty($thread['subject'])): ?><span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span><?php endif; ?>
                      <span class="name"><?php echo $op_display_name; ?></span>
                      <?php if ($op_display_role): ?><span class="role role-<?php echo htmlspecialchars($op_display_role); ?>">(<?php echo ucfirst(htmlspecialchars($op_display_role)); ?>)</span><?php endif; ?>
                      <?php if ($op_display_status === STATUS_BANNED): ?><span class="status-banned">[Banned]</span><?php endif; ?>
                      <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                      <span class="post-id">No.<?php echo $thread_id; ?></span>
                      <span class="reply-link">[<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>">View</a>]</span>
                      <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?><span class="reply-link">[<a href="#reply-form-<?php echo $thread_id; ?>">Reply</a>]</span><?php endif; ?>
                      <?php if ($total_reply_count > 0): ?><span class="reply-count">(<?php echo $total_reply_count; ?> replies)</span><?php endif; ?>
                      <?php if ($can_edit_op): ?><span class="action-link">[<a href="./?action=show_edit_form&type=thread&id=<?php echo $thread_id; ?>">Edit</a>]</span><?php endif; ?>
                      <?php if ($can_delete_op): ?><span class="action-link">[<a href="./?action=confirm_delete&type=thread&id=<?php echo $thread_id; ?>">Delete</a>]</span><?php endif; ?>
                    </p>
                    <?php echo $uploaded_media_html; ?><?php echo $linked_media_html; ?>
                    <div class="comment"><?php echo $display_comment_html; ?></div>
                  </div>

                  <?php if (!$current_user || $current_user['status'] !== STATUS_BANNED): ?>
                    <div class="reply-form-container" id="reply-form-<?php echo $thread_id; ?>" style="display: none;">
                      <h4>Reply to Thread No.<?php echo $thread_id; ?></h4>
                      <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                        <input type="hidden" name="thread_id" value="<?php echo $thread_id; ?>">
                        <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <table>
                          <?php if (!$current_user): ?>
                          <tr><th><label for="reply_username_q_<?php echo $thread_id; ?>">Username</label></th><td><input type="text" name="username" id="reply_username_q_<?php echo $thread_id; ?>" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"></td></tr>
                          <tr><th><label for="reply_password_q_<?php echo $thread_id; ?>">Password</label></th><td><input type="password" name="password" id="reply_password_q_<?php echo $thread_id; ?>"></td></tr>
                          <?php endif; ?>
                          <tr>
                            <th><label for="reply_comment_<?php echo $thread_id; ?>">Comment</label></th>
                            <td>
                              <?php $quickReplyTextareaId = 'reply_comment_' . $thread_id; ?>
                              <div class="text-formatter-toolbar">
                                <button type="button" class="format-button" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'b')"><b>B</b></button>
                                <button type="button" class="format-button" onclick="insertBbCode('<?php echo $quickReplyTextareaId; ?>', 'i')"><i>I</i></button>
                              </div>
                              <textarea name="comment" id="<?php echo $quickReplyTextareaId; ?>" rows="4" required></textarea>
                            </td>
                          </tr>
                          <tr><th><label for="reply_image_<?php echo $thread_id; ?>">File</label></th><td><input type="file" name="image" id="reply_image_<?php echo $thread_id; ?>"></td></tr>
                          <tr><th></th><td><input type="submit" value="Submit Reply"></td></tr>
                        </table>
                      </form>
                    </div>
                  <?php endif; ?>

                  <div class="reply-container">
                    <?php if ($omitted_count > 0): ?>
                      <p class="omitted-posts"><?php echo $omitted_count; ?> replies omitted. [<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>">View Full Thread</a>]</p>
                    <?php endif; ?>
                    <?php foreach ($thread_replies_preview as $reply): ?>
                      <?php
                        $reply_id = $reply['id'];
                        $reply_element_id_prefix = 'post-' . $reply_id;
                        $reply_user_info = (!empty($reply['user_id']) && isset($users_data[$reply['user_id']])) ? $users_data[$reply['user_id']] : null;
                        $reply_display_name = $reply_user_info ? htmlspecialchars($reply_user_info['username']) : ($reply['username'] ? htmlspecialchars($reply['username']) : 'Anonymous');
                        $can_edit_reply = ($current_user && $reply_user_info && $current_user['id'] === $reply_user_info['id']) || user_has_role(ROLE_MODERATOR);
                        $can_delete_reply = ($current_user && $reply_user_info && $current_user['id'] === $reply_user_info['id']) || user_has_role(ROLE_JANITOR);
                        $reply_link_media_result = process_comment_media_links($reply['comment'], $reply_element_id_prefix);
                        $reply_cleaned_comment = $reply_link_media_result['cleaned_text'];
                        $reply_linked_media_html = $reply_link_media_result['media_html'];
                        $reply_display_comment_html = (mb_strlen($reply['comment']) > COMMENT_PREVIEW_LENGTH)
                            ? format_comment(mb_substr($reply_cleaned_comment, 0, COMMENT_PREVIEW_LENGTH) . '...')
                            : format_comment($reply_cleaned_comment);
                      ?>
                      <div class="reply" id="<?php echo $reply_element_id_prefix; ?>">
                        <p class="post-info">
                          <span class="name"><?php echo $reply_display_name; ?></span>
                          <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                          <span class="post-id">No.<?php echo $reply_id; ?></span>
                          <?php if ($can_edit_reply): ?><span class="action-link">[<a href="./?action=show_edit_form&type=reply&id=<?php echo $reply_id; ?>">Edit</a>]</span><?php endif; ?>
                          <?php if ($can_delete_reply): ?><span class="action-link">[<a href="./?action=confirm_delete&type=reply&id=<?php echo $reply_id; ?>">Delete</a>]</span><?php endif; ?>
                        </p>
                        <?php echo generate_uploaded_media_html($reply, $reply_element_id_prefix); ?><?php echo $reply_linked_media_html; ?>
                        <div class="comment"><?php echo $reply_display_comment_html; ?></div>
                      </div>
                    <?php endforeach; ?>
                  </div>
                </div>
                <hr>
              <?php endforeach; ?>
              <?php if (!$viewing_thread_id): ?>
                <div class="pagination">
                  <?php if ($current_page > 1) : ?><a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a><?php else : ?><span class="disabled"><< Prev</span><?php endif; ?>
                  <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
                  <?php if ($current_page < $total_pages) : ?><a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a><?php else : ?><span class="disabled">Next >></span><?php endif; ?>
                </div>
              <?php endif; ?>
            <?php endif; ?>
          <?php endif; ?>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </body>
</html>