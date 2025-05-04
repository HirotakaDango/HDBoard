<?php
// --- Configuration ---
define('DB_FILE', __DIR__ . '/board.db'); // Database file
define('UPLOADS_DIR', __DIR__ . '/uploads'); // Base Uploads directory
define('UPLOADS_URL_PATH', 'uploads'); // Relative web path base
define('MAX_FILE_SIZE', 20 * 1024 * 1024); // 20 MB
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'webm', 'mp3', 'wav', 'ogg', 'avi', 'mov', 'flv', 'wmv']);
define('VIDEO_EXTENSIONS', ['mp4', 'webm', 'avi', 'mov', 'flv', 'wmv']);
define('AUDIO_EXTENSIONS', ['mp3', 'wav', 'ogg']);

// Define allowed channels using their short codes (used in URLs and DB)
define('ALLOWED_CHANNELS', [
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

// Define display names for channels (Key = short code, Value = Display Name)
define('CHANNEL_NAMES', [
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

// Define channels that should display an NSFW warning (use short codes)
define('NSFW_CHANNELS', [
  // Original
  'b', 'd', 'gif', 'h', 'hr', 'r9k', 's', 'soc', 'x', 'y', 'aco', 'bant', 'hc', 'hm', 'pol', 'r', 's4s', 'lgbt',
  // New (Add any relevant new ones here)
  'art', // Art can sometimes be NSFW
  'meta', // Meta discussions might touch on NSFW rules/topics
  'hist2', // History can contain sensitive/graphic content
]);

// Define Channel Categories for Navigation
$channel_categories = [
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
define('COMMENT_PREVIEW_LENGTH', 1000); // Max characters before truncation in board view
define('USERNAME_MAX_LENGTH', 50); // Max length for optional username

// --- Initialization & DB Setup ---
ini_set('display_errors', 1); // Show errors during development - DISABLE IN PRODUCTION
error_reporting(E_ALL);

// Start session for CSRF token and potential future use
if (session_status() === PHP_SESSION_NONE) {
  session_start();
}

// Generate CSRF token if one doesn't exist
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- Access Denied Page ---
if (isset($_GET['access']) && $_GET['access'] === 'denied') {
  http_response_code(403); // Forbidden
  // Simple standalone denied page
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
  exit; // Stop script execution
}


// Ensure base uploads directory exists and is writable
if (!is_dir(UPLOADS_DIR)) {
  if (!mkdir(UPLOADS_DIR, 0775, true)) {
    error_log("Error: Could not create base uploads directory at " . UPLOADS_DIR);
    die("Error: Could not create base uploads directory.");
  }
}
if (!is_writable(UPLOADS_DIR)) {
  error_log("Error: Uploads directory is not writable: " . UPLOADS_DIR);
  die("Error: The base uploads directory '" . UPLOADS_DIR . "' is not writable.");
}

try {
  $db = new PDO('sqlite:' . DB_FILE);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

  // Create/Update tables
  $db->exec("CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    username TEXT DEFAULT NULL,
    password_hash TEXT DEFAULT NULL, -- Store hash ONLY on registration post
    subject TEXT,
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_reply_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )");

  $db->exec("CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    username TEXT DEFAULT NULL,
    password_hash TEXT DEFAULT NULL, -- Store hash ONLY on registration post
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
  )");

  // Add columns if they don't exist
  function addColumnIfNotExists(PDO $db, string $tableName, string $columnName, string $columnDefinition) {
    try {
      $stmt = $db->query("PRAGMA table_info($tableName)");
      $columns = $stmt->fetchAll(PDO::FETCH_COLUMN, 1);
      if (!in_array($columnName, $columns)) {
        $db->exec("ALTER TABLE $tableName ADD COLUMN $columnName $columnDefinition");
      }
    } catch (PDOException $e) {
      error_log("Database Schema Update Error (Table: $tableName, Column: $columnName): " . $e->getMessage());
      echo "<p class='error'>Warning: Could not update database schema for column '{$columnName}'. Error: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
  }

  addColumnIfNotExists($db, 'threads', 'channel', "TEXT NOT NULL DEFAULT '" . ALLOWED_CHANNELS[0] . "'");
  addColumnIfNotExists($db, 'threads', 'username', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'threads', 'password_hash', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'replies', 'username', 'TEXT DEFAULT NULL');
  addColumnIfNotExists($db, 'replies', 'password_hash', 'TEXT DEFAULT NULL');


} catch (PDOException $e) {
  error_log("Database Connection/Setup Error: " . $e->getMessage());
  die("Database Connection/Setup Error: " . $e->getMessage());
}

// --- Helper Functions ---

/**
 * Verifies submitted password against the stored hash for a username.
 * Searches both threads and replies for the FIRST post with a hash for that user.
 */
function verify_user_password(PDO $db, string $username, string $submitted_password): bool {
  if (empty($username) || empty($submitted_password)) {
    return false;
  }
  $existing_hash = null;
  try {
    // Find the hash from the earliest post (thread or reply) by this user where a hash is stored
    // Assumes the first post with a password IS the registration post.
    // Using MIN(created_at) might be more robust than relying on ID order if imports happened etc.
    $stmt_check = $db->prepare("
      SELECT password_hash FROM (
        SELECT password_hash, created_at FROM threads WHERE username = ? AND password_hash IS NOT NULL
        UNION ALL
        SELECT password_hash, created_at FROM replies WHERE username = ? AND password_hash IS NOT NULL
      ) AS user_posts
      ORDER BY created_at ASC
      LIMIT 1
    ");
    // Consider COLLATE NOCASE for case-insensitive username check: WHERE username = ? COLLATE NOCASE
    $stmt_check->execute([$username, $username]);
    $result = $stmt_check->fetch();
    $existing_hash = $result ? $result['password_hash'] : null;

    if ($existing_hash === null) {
      error_log("No password hash found for username: " . $username);
      return false; // Username not registered with a password
    }

    return password_verify($submitted_password, $existing_hash);

  } catch (PDOException $e) {
    error_log("Password verification DB error for '{$username}': " . $e->getMessage());
    return false; // DB error during check
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
      // Optionally, try removing empty date directories - more complex, skip for now
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


// --- Standard Functions (handle_upload, get_render_media_type, format_comment, process_comment_media_links) ---

/**
 * Handles file uploads, placing them in dated subdirectories.
 * Returns the relative path (including date structure) for DB storage.
 */
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
  // Only attempt for actual image types
  $img_w = null;
  $img_h = null;
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
    $image_size = @getimagesize($file['tmp_name']);
    if ($image_size !== false) {
      $img_w = $image_size[0] ?? null;
      $img_h = $image_size[1] ?? null;
    }
  }

  // --- Create Dated Subdirectory ---
  $year = date('Y');
  $month = date('m');
  $day = date('d');
  $relative_dir_path = $year . '/' . $month . '/' . $day; // Path relative to UPLOADS_DIR
  $target_dir = UPLOADS_DIR . '/' . $relative_dir_path;

  if (!is_dir($target_dir)) {
    if (!mkdir($target_dir, 0775, true)) {
      error_log("Error: Could not create dated upload directory: " . $target_dir);
      return ['error' => 'Server error: Could not create upload directory.'];
    }
  }
  if (!is_writable(UPLOADS_DIR . '/' . $relative_dir_path)) { // Check the specific dated dir is writable
    error_log("Error: Dated upload directory is not writable: " . $target_dir);
    return ['error' => 'Server error: Upload directory is not writable.'];
  }


  // --- Generate Filename and Destination ---
  $new_filename_base = uniqid() . time(); // Base name without extension
  $new_filename = $new_filename_base . '.' . $extension;
  $relative_path_for_db = $relative_dir_path . '/' . $new_filename; // Path to store in DB
  $destination = $target_dir . '/' . $new_filename; // Full filesystem path

  // --- Move File ---
  if (move_uploaded_file($file['tmp_name'], $destination)) {
    if (!file_exists($destination)) {
      error_log("Failed confirm uploaded file existence: " . $destination);
      return ['error' => 'Failed to confirm file after move.'];
    }
    return [
      'success' => true,
      'filename' => $relative_path_for_db, // Return the relative path including date folders
      'orig_name' => basename($file['name']),
      'width' => $img_w,
      'height' => $img_h
    ];
  } else {
    error_log("Failed to move uploaded file to " . $destination . ". Source: " . $file['tmp_name'] . ". Target Dir Writable: " . (is_writable($target_dir) ? 'Yes' : 'No'));
    return ['error' => 'Failed to save uploaded file. Check permissions or disk space.'];
  }
}

function get_render_media_type($url_or_filename) {
  if (!$url_or_filename) return 'unknown';
  // YouTube check
  $youtube_regex = '/^https?:\/\/(?:www\.)?(?:m\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})(?:[?&].*)?$/i';
  if (preg_match($youtube_regex, $url_or_filename)) {
    return 'youtube';
  }
  // Extension check
  $extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
  if (in_array($extension, VIDEO_EXTENSIONS)) return 'video';
  if (in_array($extension, AUDIO_EXTENSIONS)) return 'audio';

  // Local filename check (if not starting with http/s/ftp, assume it's a local upload path)
  if (!preg_match('/^https?:\/\//', $url_or_filename) && !preg_match('/^ftp:\/\//', $url_or_filename)) {
    $local_extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
    if (in_array($local_extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
    if (in_array($local_extension, VIDEO_EXTENSIONS)) return 'video';
    if (in_array($local_extension, AUDIO_EXTENSIONS)) return 'audio';
  }

  return 'unknown';
}

function format_comment($comment) {
  $comment = (string) ($comment ?? '');
  // 1. Sanitize HTML
  $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
  // 2. Linkify URLs (Exclude URLs already within a tag like href or src)
  $comment = preg_replace_callback(
    '/(?<![\'"])(?<![=\/])\b(https?|ftp):\/\/([^\s<>"\'`]+)/i', // Added \b word boundary
    function ($matches) {
      $url = $matches[0];
      // Decode for display, handle special chars safely
      $decoded_display = htmlspecialchars_decode($matches[2], ENT_QUOTES);
      // Shorten display if too long
      $display_url = (mb_strlen($decoded_display) > 50) ? mb_substr($decoded_display, 0, 47) . '...' : $decoded_display;
      // Ensure URL is valid and escaped for href attribute
      $safe_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
      // Display URL is shown decoded but HTML escaped for display within the link text
      return '<a href="' . $safe_url . '" target="_blank" rel="noopener noreferrer">' . htmlspecialchars(urldecode($matches[1] . '://' . $display_url), ENT_QUOTES, 'UTF-8') . '</a>';
    },
    $comment
  );
  // 3. nl2br
  $comment = nl2br($comment, false);
  // 4. Greentext (apply after nl2br to handle line breaks correctly)
  $comment = preg_replace('/(^<br\s*\/?>|\n|^)(>[^<].*?)$/m', '$1<span class="greentext">$2</span>', $comment); // Handles <br> or newline starting line
  $comment = preg_replace('/(^\s*)(>[^<].*?)$/m', '$1<span class="greentext">$2</span>', $comment); // For lines not starting with <br> or newline (first line)
  // 5. Reply Links (>>123)
  $comment = preg_replace('/>>(\d+)/', '<a href="#post-$1" class="reply-mention">>>$1</a>', $comment);
  return $comment;
}

function process_comment_media_links($text, $post_element_id) {
  $media_html = '';
  $cleaned_text = $text;
  $link_counter = 0;
  // Regex to find URLs that are NOT already part of an img src or a href attribute
  $url_regex = '/(?<!src=["\'])(?<!href=["\'])(?<!data-media-url=["\'])\b(https?|ftp):\/\/[^\s<>"]+/i'; // Added check for data-media-url

  if (preg_match_all($url_regex, $text, $matches, PREG_OFFSET_CAPTURE)) {
    // Process matches in reverse order to handle offsets correctly after removing
    $matches_reversed = array_reverse($matches[0]);
    $media_items_to_append = [];

    foreach ($matches_reversed as $match) {
      $url = $match[0];
      $offset = $match[1];
      $render_type = get_render_media_type($url);

      if ($render_type !== 'unknown') {
        $media_items_to_append[] = ['url' => $url, 'render_type' => $render_type];
        // Remove the media URL from the original text
        $cleaned_text = mb_substr($cleaned_text, 0, $offset) . mb_substr($cleaned_text, $offset + mb_strlen($url));
      }
    }

    // Generate HTML for media items found
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

      $media_html .= "
        <div class='file-info comment-link-info'>
          <div class='media-toggle'>
            <button class='show-media-btn'
              data-media-id='{$media_id}'
              data-media-url='{$safe_url}'
              data-media-type='{$render_type}'>{$button_text}</button>
          </div>
          <span class='file-details'>
            Link: <a href='{$safe_url}' target='_blank' rel='noopener noreferrer'>{$safe_url}</a>
          </span>
        </div>
        <div id='media-container-{$media_id}' class='media-container' style='display:none;'></div>";
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
  // Use filter_input for GET parameters too
  $viewing_thread_id = filter_input(INPUT_GET, 'thread', FILTER_VALIDATE_INT);
  // Ensure filter_input didn't return false (invalid integer) or null (not set)
  if ($viewing_thread_id === false || $viewing_thread_id === null) {
    $viewing_thread_id = null; // Treat invalid/missing as null
  }
}

// --- Global Variables for Actions/Messages ---
$action_error = null;
$action_success = null;
$show_action_form = null; // Controls display of password/edit forms
$post_data_for_form = null; // Holds data for pre-filling edit form

// --- Handle Actions (Delete/Edit) ---
if (isset($_REQUEST['action'])) { // Use $_REQUEST to catch GET/POST
  $action = $_REQUEST['action'];

  // --- FIX START (Replacing INPUT_REQUEST) ---
  // Fetch raw values from $_REQUEST (which combines GET and POST)
  $post_type_raw = $_REQUEST['type'] ?? null;
  $post_id_raw = $_REQUEST['id'] ?? null;

  // Sanitize/Validate using filter_var
  $post_type = $post_type_raw ? filter_var($post_type_raw, FILTER_SANITIZE_SPECIAL_CHARS) : null;
  // Use FILTER_NULL_ON_FAILURE to ensure $post_id is null if validation fails or input is missing
  $post_id = $post_id_raw ? filter_var($post_id_raw, FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE) : null;
  // --- FIX END ---

  $submitted_password = $_POST['password'] ?? null; // Only relevant for POST steps
  $submitted_csrf = $_POST['csrf_token'] ?? null;

  // Validation now correctly uses the filtered $post_type and $post_id
  if (!in_array($post_type, ['thread', 'reply']) || !$post_id) {
    $action_error = "Invalid request parameters.";
  } elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf))) {
    // CSRF token check for all POST actions related to edit/delete
    error_log("CSRF token mismatch for action: " . $action);
    header("Location: ./?access=denied&error=csrf"); // Redirect to denied page
    exit;
  } else {
    // Fetch the post to get username and file path
    $post_data = null;
    try {
      if ($post_type === 'thread') {
        $stmt = $db->prepare("SELECT id, channel, username, password_hash, subject, comment, image FROM threads WHERE id = ?");
      } else { // reply
        $stmt = $db->prepare("SELECT r.id, r.username, r.password_hash, r.comment, r.image, t.channel, r.thread_id FROM replies r JOIN threads t ON r.thread_id = t.id WHERE r.id = ?");
      }
      $stmt->execute([$post_id]);
      $post_data = $stmt->fetch();
    } catch (PDOException $e) {
      error_log("DB Error fetching post for action {$action}: " . $e->getMessage());
      $action_error = "Database error fetching post details.";
    }

    if (!$post_data) {
      $action_error = ucfirst($post_type) . " not found.";
    } elseif (empty($post_data['username'])) {
      $action_error = "Cannot modify anonymous posts.";
    } else {
      // Post exists and has a username, proceed with action logic
      $post_username = $post_data['username'];
      $target_channel = $post_data['channel']; // Channel the post belongs to
      $redirect_url_base = "./?channel=" . urlencode($target_channel);
      if ($post_type === 'reply') {
        $redirect_url_thread = $redirect_url_base . "&thread=" . $post_data['thread_id'];
      } else {
        $redirect_url_thread = $redirect_url_base; // Redirect to board for deleted thread
      }


      switch ($action) {
        // --- DELETE ACTIONS ---
        case 'confirm_delete': // Step 1: Show password confirmation form
          $show_action_form = 'delete_confirm';
          $post_data_for_form = $post_data; // Pass data to render the form
          $post_data_for_form['type'] = $post_type; // Explicitly add type for form generation
          // No password check needed yet, just display the form
          break;

        case 'delete': // Step 2: Process password and perform deletion (POST)
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("Location: ./?access=denied&error=method");
            exit;
          }
          if (verify_user_password($db, $post_username, $submitted_password)) {
            try {
              $db->beginTransaction();
              // Delete file first
              $file_deleted = delete_post_file($post_data['image']);
              if (!$file_deleted && $post_data['image']) {
                // Optionally rollback if file deletion fails, or just log it
                error_log("Could not delete file for {$post_type} ID {$post_id}, but proceeding with DB deletion.");
              }

              // Delete DB record
              if ($post_type === 'thread') {
                $stmt_del = $db->prepare("DELETE FROM threads WHERE id = ?");
                // Replies deleted by CASCADE constraint
              } else { // reply
                $stmt_del = $db->prepare("DELETE FROM replies WHERE id = ?");
              }
              $stmt_del->execute([$post_id]);
              $db->commit();
              $action_success = ucfirst($post_type) . " deleted successfully.";
              // Redirect after successful deletion
              header("Location: " . $redirect_url_thread . "&deleted=" . $post_id);
              exit;
            } catch (PDOException $e) {
              if ($db->inTransaction()) $db->rollBack();
              error_log("DB Error deleting {$post_type} ID {$post_id}: " . $e->getMessage());
              $action_error = "Database error during deletion.";
            }
          } else {
            // Password failed - show confirmation form again with error
            $action_error = "Incorrect password.";
            $show_action_form = 'delete_confirm'; // Re-show form
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type; // Add type
          }
          break;

        // --- EDIT ACTIONS ---
        case 'show_edit_form': // Step 1: Show password confirmation form for editing
          $show_action_form = 'edit_confirm';
          $post_data_for_form = $post_data;
          $post_data_for_form['type'] = $post_type; // Add type
          // No password check needed yet
          break;

        case 'edit': // Step 2: Process password verification (POST from confirm form)
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("Location: ./?access=denied&error=method");
            exit;
          }
          if (verify_user_password($db, $post_username, $submitted_password)) {
            // Password correct! Store verification in session and show actual edit form.
            $_SESSION['edit_verified'] = ['type' => $post_type, 'id' => $post_id, 'time' => time()];
            $show_action_form = 'edit_fields'; // Show the form with fields
            $post_data_for_form = $post_data; // Pass data for pre-filling
            $post_data_for_form['type'] = $post_type; // Add type
          } else {
            // Password failed - show confirmation form again with error
            $action_error = "Incorrect password.";
            $show_action_form = 'edit_confirm'; // Re-show confirmation form
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type; // Add type
          }
          break;

        case 'save_edit': // Step 3: Process the submitted edit form (POST)
          if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("Location: ./?access=denied&error=method");
            exit;
          }
          // Check if user was recently verified for THIS post
          if (
            empty($_SESSION['edit_verified']) ||
            $_SESSION['edit_verified']['type'] !== $post_type ||
            $_SESSION['edit_verified']['id'] !== $post_id ||
            (time() - $_SESSION['edit_verified']['time'] > 300)
          ) { // 5 min timeout

            unset($_SESSION['edit_verified']);
            error_log("Edit verification failed or timed out for {$post_type} ID {$post_id}");
            header("Location: ./?access=denied&error=timeout");
            exit;
          }

          // User is verified, proceed with update
          $new_comment = trim($_POST['comment'] ?? '');
          $new_subject = ($post_type === 'thread') ? trim($_POST['subject'] ?? '') : null; // Only threads have subjects

          if (empty($new_comment)) {
            $action_error = "Comment cannot be empty.";
            $show_action_form = 'edit_fields'; // Re-show edit form with error
            // We need to pass the originally fetched data AND the attempted data
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type; // Add type
            $post_data_for_form['comment_attempt'] = $new_comment;
            $post_data_for_form['subject_attempt'] = $new_subject;

          } elseif (mb_strlen($new_comment) > 4000) {
            $action_error = "Post content is too long (max 4000 characters).";
            $show_action_form = 'edit_fields'; // Re-show edit form with error
            $post_data_for_form = $post_data;
            $post_data_for_form['type'] = $post_type; // Add type
            $post_data_for_form['comment_attempt'] = $new_comment;
            $post_data_for_form['subject_attempt'] = $new_subject;
          } else {
            try {
              if ($post_type === 'thread') {
                $stmt_update = $db->prepare("UPDATE threads SET subject = ?, comment = ? WHERE id = ?");
                $stmt_update->execute([$new_subject, $new_comment, $post_id]);
              } else { // reply
                $stmt_update = $db->prepare("UPDATE replies SET comment = ? WHERE id = ?");
                $stmt_update->execute([$new_comment, $post_id]);
              }
              unset($_SESSION['edit_verified']); // Clear verification flag
              $action_success = ucfirst($post_type) . " updated successfully.";
              // Redirect back to the post after successful edit
              $post_anchor = "#post-" . $post_id;
              header("Location: " . $redirect_url_thread . "&edited=" . $post_id . $post_anchor);
              exit;
            } catch (PDOException $e) {
              error_log("DB Error updating {$post_type} ID {$post_id}: " . $e->getMessage());
              $action_error = "Database error during update.";
              // Don't automatically show form again on DB error, show generic error.
            }
          }
          break;

        default:
          $action_error = "Unknown action specified.";
      }
    }
  }
  // If any action resulted in an error BUT didn't redirect or specifically set $show_action_form,
  // we might want to prevent the normal page load. A simple way is to just show the error.
  // However, the current logic mostly handles this by re-showing forms or redirecting.
}


// --- Handle Post Request (New Thread/Reply) ---
$post_error = null;
$post_success = null; // Note: Redirects usually happen on success, so this might not be shown often.

// Only process POST if we are on a valid channel page AND no edit/delete action is overriding
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action']) && !$show_board_index && isset($_POST['comment']) && empty($action_error) && empty($show_action_form)) {
  // CSRF Check for regular posts
  $submitted_csrf = $_POST['csrf_token'] ?? null;
  if (!isset($submitted_csrf) || !hash_equals($_SESSION['csrf_token'], $submitted_csrf)) {
    error_log("CSRF token mismatch for new post/reply.");
    $post_error = "Invalid form submission. Please try again.";
    // Don't proceed with post handling
  } else {

    $comment_raw = trim($_POST['comment'] ?? '');
    $subject = trim($_POST['subject'] ?? '');
    $thread_id = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT);
    // Ensure filter_input didn't return false (invalid integer) or null (not set)
    if ($thread_id === false || $thread_id === null) {
      $thread_id = null; // Treat invalid/missing as null
    }

    // The channel code must match the current page's channel code for security
    $posted_channel_code = trim($_POST['channel'] ?? '');

    // Basic validation first
    if (empty($posted_channel_code) || $posted_channel_code !== $current_channel_code) {
      $post_error = "Invalid channel specified for post.";
    }

    // --- Username and Password Handling (Only proceed if channel is valid) ---
    if ($post_error === null) {
      $input_username = trim($_POST['username'] ?? '');
      $input_password = $_POST['password'] ?? ''; // Keep raw password for verification check
      $db_username_to_store = null;
      $db_password_hash_to_store = null; // Will store hash ONLY on registration

      // Validate username length first
      if (mb_strlen($input_username) > USERNAME_MAX_LENGTH) {
        $post_error = "Username is too long (max " . USERNAME_MAX_LENGTH . " characters).";
      } elseif (!empty($input_username)) {
        // Username provided, check registration status and password
        $existing_hash = null;
        try {
          // Find the first post (thread or reply) by this user that has a password hash set.
          $stmt_check = $db->prepare("
            SELECT password_hash FROM (
              SELECT password_hash, created_at FROM threads WHERE username = ? AND password_hash IS NOT NULL
              UNION ALL
              SELECT password_hash, created_at FROM replies WHERE username = ? AND password_hash IS NOT NULL
            ) AS user_posts
            ORDER BY created_at ASC
            LIMIT 1
          ");
          $stmt_check->execute([$input_username, $input_username]);
          $result = $stmt_check->fetch();
          $existing_hash = $result ? $result['password_hash'] : null; // This is the hash stored during registration

        } catch (PDOException $e) {
          error_log("Username check failed for '{$input_username}': " . $e->getMessage());
          $post_error = "Database error during username check.";
        }

        if ($post_error === null) { // Proceed only if DB check didn't fail
          if ($existing_hash !== null) {
            // Username is REGISTERED (found an existing password hash)
            if (empty($input_password)) {
              $post_error = "Password required for registered username '" . htmlspecialchars($input_username) . "'.";
            } elseif (!password_verify($input_password, $existing_hash)) {
              // Password provided, but it's incorrect
              $post_error = "Invalid password for username '" . htmlspecialchars($input_username) . "'.";
            } else {
              // Password is correct! User is verified for this post.
              $db_username_to_store = $input_username;
              // Do NOT store the hash again. Store NULL for subsequent posts.
              $db_password_hash_to_store = null;
            }
          } else {
            // Username is NOT REGISTERED (or only used without password before)
            if (empty($input_password)) {
              // Allow posting with a username but no password (they won't be registered, username is just a tag)
              $db_username_to_store = $input_username;
              $db_password_hash_to_store = null; // No hash stored for non-registered use
            } else {
              // First time use WITH a password - Register!
              $db_username_to_store = $input_username;
              // Hash the password and store it THIS TIME ONLY.
              $db_password_hash_to_store = password_hash($input_password, PASSWORD_DEFAULT);
              if ($db_password_hash_to_store === false) {
                $post_error = "Failed to process password during registration.";
                error_log("password_hash() failed during registration for '{$input_username}'.");
              }
            }
          }
        }
      } else {
        // Username field is empty, post anonymously
        $db_username_to_store = null;
        $db_password_hash_to_store = null;
      }
    }


    // --- Continue with the rest of the POST validation ONLY if $post_error is still null ---
    if ($post_error === null) {
      // Check channel consistency if thread_id is provided
      if ($thread_id) {
        try {
          $stmt_check_thread_channel = $db->prepare("SELECT channel FROM threads WHERE id = ?");
          $stmt_check_thread_channel->execute([$thread_id]);
          $thread_channel_data = $stmt_check_thread_channel->fetch();
          if (!$thread_channel_data) {
            $post_error = "Thread not found.";
          } elseif ($thread_channel_data['channel'] !== $current_channel_code) {
            $post_error = "Attempting to reply to a thread from the wrong channel page.";
          }
        } catch (PDOException $e) {
          error_log("Database error checking thread channel for reply: " . $e->getMessage());
          $post_error = "Database error verifying thread.";
        }
      }

      if ($post_error === null) { // Proceed only if thread channel check passed
        // Content check (after username/password is handled)
        $temp_media_check = process_comment_media_links($comment_raw, 'temp-validation');
        $has_text_content = !empty(trim($temp_media_check['cleaned_text']));
        $has_media_links = !empty($temp_media_check['media_html']);
        $has_file = isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE;

        if ($show_board_index) { // Should not happen due to initial check, but double-check
          $post_error = "Cannot post from the board index.";
        } elseif (!$thread_id && !$has_text_content && !$has_file && !$has_media_links) {
          // New thread requires at least comment, file, or media link
          $post_error = "A comment, a file, or media links are required for a new thread.";
        } elseif ($thread_id && !$has_text_content && !$has_file && !$has_media_links) {
          // Reply requires at least comment, file, or media link
          $post_error = "A comment, a file, or media links are required for a reply.";
        } elseif (mb_strlen($comment_raw) > 4000) {
          $post_error = "Post content is too long (max 4000 characters).";
        } else {
          // Handle file upload
          $upload_result = handle_upload('image');

          if (isset($upload_result['error'])) {
            $post_error = $upload_result['error'];
          } else {
            // Ready to insert into DB
            try {
              $db->beginTransaction();

              $image_relative_path = $upload_result['filename'] ?? null;
              $image_orig_name = $upload_result['orig_name'] ?? null;
              $image_w = $upload_result['width'] ?? null;
              $image_h = $upload_result['height'] ?? null;

              // Final content check again
              if ($image_relative_path === null && !$has_text_content && !$has_media_links) {
                $db->rollBack();
                $post_error = "A comment, a file, or media links are required.";
              } else {
                if ($thread_id) { // Posting a Reply
                  $stmt = $db->prepare("INSERT INTO replies (thread_id, username, password_hash, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                  $stmt->execute([
                    $thread_id,
                    $db_username_to_store,
                    $db_password_hash_to_store,
                    $comment_raw,
                    $image_relative_path,
                    $image_orig_name, $image_w, $image_h
                  ]);
                  $new_post_id = $db->lastInsertId();

                  // Update last_reply_at for the thread
                  $stmt_update = $db->prepare("UPDATE threads SET last_reply_at = CURRENT_TIMESTAMP WHERE id = ?");
                  $stmt_update->execute([$thread_id]);

                  $db->commit();
                  // Redirect to the post
                  $redirect_params = ['channel' => $current_channel_code, 'thread' => $thread_id];
                  $redirect_url = './?' . http_build_query($redirect_params) . '&ts=' . time() . '#post-' . $new_post_id;
                  header("Location: " . $redirect_url);
                  exit;

                } else { // Posting a New Thread
                  $stmt = $db->prepare("INSERT INTO threads (channel, username, password_hash, subject, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                  $stmt->execute([
                    $current_channel_code,
                    $db_username_to_store,
                    $db_password_hash_to_store,
                    $subject, $comment_raw,
                    $image_relative_path,
                    $image_orig_name, $image_w, $image_h
                  ]);
                  $new_post_id = $db->lastInsertId();

                  $db->commit();
                  // Redirect to the board
                  $redirect_params = ['channel' => $current_channel_code];
                  $redirect_url = './?' . http_build_query($redirect_params) . '&newthread=' . $new_post_id . '&ts=' . time();
                  header("Location: " . $redirect_url);
                  exit;
                }
              }
            } catch (PDOException $e) {
              if ($db->inTransaction()) {
                $db->rollBack();
              }
              error_log("Database Post Error: " . $e->getMessage());
              $post_error = "Database Error: Could not save post. " . htmlspecialchars($e->getMessage());
            }
          } // End upload success check
        } // End basic validation checks
      } // End thread channel mismatch check
    } // End initial $post_error === null check (username/password validation)
  } // End CSRF check
} // End POST request handling (new post/reply)


// --- Fetch Data for Display (only if no action form is being shown) ---
$threads = [];
$replies_to_display = [];
$reply_counts = [];
$total_threads = 0;
$total_pages = 1;
$thread_op = null;
$current_page = 1;
$board_index_data = [];

// Only fetch page data if we are not currently displaying an action form (like edit or delete confirm)
// OR if an action resulted in an error that doesn't require re-showing a form (e.g., DB error on delete)
$fetch_page_data = empty($show_action_form) || (!empty($action_error) && !in_array($show_action_form, ['delete_confirm', 'edit_confirm', 'edit_fields']));

if ($fetch_page_data) {
  if ($show_board_index) {
    // --- Board Index View (Home Page) ---
    try {
      $thread_count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
      $reply_count_stmt = $db->prepare("SELECT COUNT(r.id) FROM replies r JOIN threads t ON r.thread_id = t.id WHERE t.channel = ?");

      foreach (ALLOWED_CHANNELS as $channel_code) {
        $display_name = CHANNEL_NAMES[$channel_code] ?? $channel_code;
        $thread_count_stmt->execute([$channel_code]);
        $thread_count = $thread_count_stmt->fetchColumn();
        $reply_count_stmt->execute([$channel_code]);
        $reply_count = $reply_count_stmt->fetchColumn();
        $board_index_data[$channel_code] = ['code' => $channel_code, 'name' => $display_name, 'total_posts' => $thread_count + $reply_count];
      }
      // Order the board_index_data according to channel categories
      $ordered_board_index_data = [];
      foreach ($channel_categories as $category_name => $category_channels) {
        foreach ($category_channels as $channel_code) {
          if (isset($board_index_data[$channel_code])) {
            $ordered_board_index_data[$channel_code] = $board_index_data[$channel_code];
          } else {
            if (!in_array($channel_code, ALLOWED_CHANNELS)) {
              error_log("Warning: Channel code '{$channel_code}' listed in categories is not in ALLOWED_CHANNELS.");
            } else {
              error_log("Warning: Channel code '{$channel_code}' in categories unexpectedly missing from board_index_data.");
            }
          }
        }
      }
      foreach (ALLOWED_CHANNELS as $channel_code) {
        if (!isset($ordered_board_index_data[$channel_code]) && isset($board_index_data[$channel_code])) {
          $ordered_board_index_data[$channel_code] = $board_index_data[$channel_code];
        }
      }
      $board_index_data = $ordered_board_index_data;

    } catch (PDOException $e) {
      error_log("Database Fetch Error (Board Index Cards): " . $e->getMessage());
      die("Database Fetch Error: " . $e->getMessage());
    }

  } else {
    // --- Channel or Thread View ---
    try {
      if ($viewing_thread_id) {
        // --- Thread View ---
        $stmt = $db->prepare("SELECT id, channel, username, subject, comment, image, image_orig_name, image_w, image_h, created_at FROM threads WHERE id = ? AND channel = ?");
        $stmt->execute([$viewing_thread_id, $current_channel_code]);
        $thread_op = $stmt->fetch();

        if ($thread_op) {
          $replies_stmt = $db->prepare("SELECT id, thread_id, username, comment, image, image_orig_name, image_w, image_h, created_at FROM replies WHERE thread_id = ? ORDER BY created_at ASC");
          $replies_stmt->execute([$viewing_thread_id]);
          $replies_to_display[$viewing_thread_id] = $replies_stmt->fetchAll();
          $reply_counts[$viewing_thread_id] = count($replies_to_display[$viewing_thread_id]);
          $threads = [$thread_op]; // Put the single thread into the $threads array
        } else {
          // Set error message but allow page structure to render below
          $action_error = $action_error ?? ("Thread with ID " . htmlspecialchars($viewing_thread_id) . " not found in channel /" . htmlspecialchars($current_channel_code) . "/.");
          $viewing_thread_id = null; // Force board view rendering (or just error)
          // No threads will be loaded, page will show error.
        }
      }

      // --- Board View (or initial load if $viewing_thread_id is null/invalid) ---
      if (!$viewing_thread_id) {
        $current_page = max(1, filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT) ?: 1);
        if ($current_page === false || $current_page === null) {
          $current_page = 1; // Default to 1 if invalid/missing
        }

        $count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
        $count_stmt->execute([$current_channel_code]);
        $total_threads = $count_stmt->fetchColumn();
        $total_pages = max(1, ceil($total_threads / THREADS_PER_PAGE));
        $current_page = min($current_page, $total_pages); // Ensure current page is not beyond total pages
        $offset = ($current_page - 1) * THREADS_PER_PAGE;

        // Fetch threads for the current page
        $threads_stmt = $db->prepare("SELECT id, channel, username, subject, comment, image, image_orig_name, image_w, image_h, created_at, last_reply_at FROM threads WHERE channel = ? ORDER BY last_reply_at DESC LIMIT ? OFFSET ?");
        $threads_stmt->bindValue(1, $current_channel_code, PDO::PARAM_STR);
        $threads_stmt->bindValue(2, THREADS_PER_PAGE, PDO::PARAM_INT);
        $threads_stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $threads_stmt->execute();
        $threads = $threads_stmt->fetchAll();

        // Fetch reply previews/counts for the threads on the current page
        $threads_on_page_ids = array_column($threads, 'id');
        if (!empty($threads_on_page_ids)) {
          $placeholders = implode(',', array_fill(0, count($threads_on_page_ids), '?'));

          // Fetch counts
          $count_stmt = $db->prepare("SELECT thread_id, COUNT(*) as count FROM replies WHERE thread_id IN ($placeholders) GROUP BY thread_id");
          $count_stmt->execute($threads_on_page_ids);
          $reply_counts_fetched = $count_stmt->fetchAll(PDO::FETCH_KEY_PAIR);
          // Ensure all thread IDs have an entry in reply_counts, even if 0
          foreach ($threads_on_page_ids as $tid) {
            $reply_counts[$tid] = $reply_counts_fetched[$tid] ?? 0;
          }


          // Fetch ALL replies for threads on page to get LAST N
          $all_replies_for_page = [];
          $replies_stmt = $db->prepare("SELECT id, thread_id, username, comment, image, image_orig_name, image_w, image_h, created_at FROM replies WHERE thread_id IN ($placeholders) ORDER BY created_at ASC");
          $replies_stmt->execute($threads_on_page_ids);
          while ($reply = $replies_stmt->fetch()) {
            $all_replies_for_page[$reply['thread_id']][] = $reply;
          }

          // Slice the last N
          foreach ($all_replies_for_page as $tid => $thread_replies) {
            $start_index = max(0, count($thread_replies) - REPLIES_PREVIEW_COUNT);
            $replies_to_display[$tid] = array_slice($thread_replies, $start_index);
          }
          // Ensure replies_to_display has entries for threads with 0 replies
          foreach ($threads_on_page_ids as $tid) {
            if (!isset($replies_to_display[$tid])) {
              $replies_to_display[$tid] = [];
            }
          }
        }
      }
    } catch (PDOException $e) {
      error_log("Database Fetch Error (Channel/Thread): " . $e->getMessage());
      die("Database Fetch Error: " . $e->getMessage());
    }
  }
} // end if ($fetch_page_data)

?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/HDBoard.png">
    <title><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code ?? '...') . '/ - ' . htmlspecialchars($current_channel_display_name ?? '...') . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></title>
    <style>
      /* --- Base Styles (UNCHANGED) --- */
      :root {
        --bg-color: #1a1a1a; --text-color: #e0e0e0; --border-color: #444; --post-bg: #282828;
        --header-bg: #333; --link-color: #7aa2f7; --link-hover: #c0caf5; --accent-red: #f7768e;
        --accent-green: #9ece6a; --accent-blue: #4f6dac; --greentext-color: #9ece6a; --reply-mention-color: #f7768e;
        --form-bg: #303030; --input-bg: #404040; --input-text: #e0e0e0; --input-border: #555;
        --button-bg: #555; --button-hover-bg: #666; --button-text: #e0e0e0; --warning-bg: #5c2424;
        --warning-border: #a04040; --warning-text: #f7768e; --success-bg: #2a502a; --success-border: #4a804a;
        --success-text: #9ece6a; --error-bg: var(--warning-bg); --error-border: var(--warning-border);
        --error-text: var(--warning-text); --code-bg: #333; --code-text: #ccc; --board-index-item-bg: var(--post-bg);
        --board-index-item-border: var(--border-color); --board-index-item-hover-bg: #383838;
        --summary-bg: var(--button-bg); --summary-hover-bg: var(--button-hover-bg);
        --action-form-bg: var(--form-bg);
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
        text-align: center;
      }
      header h1 {
        color: var(--accent-red);
        margin: 5px 0;
        font-size: 1.8em;
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
      .post-form, .action-form { /* Combined for similar base styles */
        background-color: var(--form-bg);
        border: 1px solid var(--border-color);
        padding: 15px;
        margin-bottom: 20px;
      }
      .action-form {
        background-color: var(--action-form-bg); /* Can be different if needed */
      }
      .post-form h2, .action-form h2, .action-form h3 { /* Style the H2/H3 */
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

      /* Form table styles */
      .post-form table, .reply-form-container table, .action-form table {
        border-collapse: collapse;
        width: 100%;
      }
      .post-form th, .post-form td, .reply-form-container th, .reply-form-container td, .action-form th, .action-form td {
        padding: 6px;
        vertical-align: top;
        text-align: left;
      }
      .post-form th, .reply-form-container th, .action-form th {
        width: 130px;
        text-align: right;
        font-weight: bold;
        color: var(--text-color);
        padding-right: 10px;
      }
      .reply-form-container th, .action-form th {
        width: 110px; /* Slightly less width for reply/action forms */
      }
      .post-form td, .reply-form-container td, .action-form td {
        width: auto;
      }
      .post-form input[type="text"], .post-form input[type="password"], .post-form textarea, .post-form select,
      .reply-form-container input[type="text"], .reply-form-container input[type="password"], .reply-form-container textarea,
      .action-form input[type="text"], .action-form input[type="password"], .action-form textarea {
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
      .post-form input[type="submit"], .reply-form-container input[type="submit"], .action-form input[type="submit"] {
        padding: 6px 15px;
        font-weight: bold;
        cursor: pointer;
        background-color: var(--button-bg);
        color: var(--button-text);
        border: 1px solid var(--input-border);
        border-radius: 3px;
      }
      .post-form input[type="submit"]:hover, .reply-form-container input[type="submit"]:hover, .action-form input[type="submit"]:hover {
        background-color: var(--button-hover-bg);
      }
      .post-form small, .reply-form-container small, .action-form small {
        color: #aaa;
        font-size: 0.9em;
      }
      hr {
        border: 0;
        border-top: 1px solid var(--border-color);
        margin: 25px 0;
      }
      .board-index-list { list-style: none; padding: 0; margin: 20px 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; }
      .board-index-list li { background-color: var(--board-index-item-bg); border: 1px solid var(--board-index-item-border); border-radius: 4px; transition: background-color 0.2s ease; }
      .board-index-list li:hover { background-color: var(--board-index-item-hover-bg); }
      .board-index-list a { display: block; padding: 10px 15px; color: var(--link-color); text-decoration: none; }
      .board-index-list a:hover { color: var(--link-hover); text-decoration: none; }
      .board-index-list .board-code { font-weight: bold; color: var(--accent-green); font-size: 1.1em; }
      .board-index-list .board-name { display: block; margin-top: 3px; font-size: 0.95em; color: var(--text-color); }
      .board-index-list .board-post-count { display: block; font-size: 0.85em; color: #aaa; margin-top: 5px; text-align: right; }
      .thread, .reply { background-color: var(--post-bg); border: 1px solid var(--border-color); margin-bottom: 10px; padding: 8px 12px; word-wrap: break-word; overflow-wrap: break-word; }
      .reply-container { margin-left: 20px; margin-top: 10px; }
      .reply { margin-top: 5px; padding: 6px 10px; max-width: calc(100% - 20px); min-width: 200px; box-sizing: border-box; }
      .post-info { margin-bottom: 3px; font-size: 0.95em; }
      .post-info .subject { color: var(--accent-blue); margin-right: 5px; font-weight: bold; }
      .post-info .name { color: var(--accent-green); font-weight: bold; margin-right: 8px; }
      .post-info .time, .post-info .post-id { font-size: 0.9em; color: #bbb; font-weight: normal; margin-left: 8px; }
      .post-info .reply-link, .post-info .action-link { /* Combined reply and action links */
        font-size: 0.9em;
        color: #bbb;
        text-decoration: none;
        font-weight: normal;
        margin-left: 8px;
      }
      .post-info .reply-link a, .post-info .action-link a { color: var(--link-color); }
      .post-info .reply-link a:hover, .post-info .action-link a:hover { color: var(--link-hover); }
      .post-info .action-link a { /* Make delete/edit slightly different maybe */
        color: var(--accent-red);
      }
      .post-info .action-link a:hover {
        color: var(--link-hover);
      }
      .post-info .reply-count { font-size: 0.9em; color: #bbb; font-weight: normal; margin-left: 5px; }
      .file-info { font-size: 0.9em; color: #ccc; margin-bottom: 8px; display: flex; align-items: flex-start; flex-wrap: wrap; gap: 5px 10px; border-bottom: 1px dashed var(--border-color); padding-bottom: 5px; margin-top: 5px; }
      .file-info:last-of-type { border-bottom: none; margin-bottom: 10px; }
      .file-info .media-toggle { flex-shrink: 0; }
      .file-info .media-toggle button.show-media-btn { padding: 4px 8px; cursor: pointer; font-size: 0.9em; background-color: var(--button-bg); border: 1px solid var(--input-border); border-radius: 3px; color: var(--button-text); line-height: 1.2; text-transform: none; white-space: normal; text-align: center; }
      .file-info .media-toggle button.show-media-btn:hover { background-color: var(--button-hover-bg); }
      .file-details { flex-grow: 1; line-height: 1.4; word-break: break-all; }
      .file-details a { color: var(--link-color); text-decoration: underline; }
      .file-details a:hover { color: var(--link-hover); }
      .media-container { margin-top: 8px; margin-bottom: 10px; border: 1px dashed var(--border-color); padding: 5px; display: none; max-width: 100%; box-sizing: border-box; overflow: hidden; background-color: var(--bg-color); }
      .media-container img, .media-container video, .media-container iframe { display: block; max-width: 100%; height: auto; margin: 0 auto; background-color: #000; }
      .media-container audio { display: block; width: 100%; min-height: 30px; height: auto; margin: 0 auto; }
      .youtube-embed-container, .video-embed-container { margin: 5px 0; position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; background: #000; }
      .youtube-embed-container iframe, .video-embed-container video { position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none; }
      .comment { margin-top: 10px; line-height: 1.5; overflow-wrap: break-word; word-break: break-word; color: var(--text-color); }
      .comment-truncated { display: block; }
      .comment-full { display: none; }
      .show-full-text-btn { display: inline-block; padding: 2px 5px; font-size: 0.8em; cursor: pointer; margin-left: 5px; margin-top: 5px; background-color: var(--button-bg); border: 1px solid var(--input-border); border-radius: 3px; color: var(--button-text); }
      .show-full-text-btn:hover { background-color: var(--button-hover-bg); }
      .greentext { color: var(--greentext-color); }
      .reply-mention { color: var(--reply-mention-color); text-decoration: none; font-weight: bold; }
      .reply-mention:hover { color: var(--link-hover); text-decoration: underline; }
      .omitted-posts { font-size: 0.9em; color: #aaa; margin-left: 20px; margin-top: 5px; margin-bottom: 10px; }
      .omitted-posts a { color: var(--link-color); text-decoration: none; }
      .omitted-posts a:hover { text-decoration: underline; }
      .error, .success { font-weight: bold; border: 1px solid; padding: 10px; margin-bottom: 15px; border-radius: 4px; }
      .error { color: var(--error-text); background-color: var(--error-bg); border-color: var(--error-border); }
      .success { color: var(--success-text); background-color: var(--success-bg); border-color: var(--success-border); }
      .pagination { text-align: center; margin: 20px 0; font-size: 1.1em; }
      .pagination a, .pagination span { display: inline-block; padding: 5px 10px; margin: 0 3px; border: 1px solid var(--border-color); background-color: var(--post-bg); text-decoration: none; color: var(--link-color); border-radius: 3px; }
      .pagination a:hover { background-color: var(--button-hover-bg); border-color: var(--link-hover); }
      .pagination span.current-page { background-color: var(--accent-red); color: var(--button-text); font-weight: bold; border-color: var(--accent-red); }
      .pagination span.disabled { color: #888; cursor: not-allowed; background-color: var(--header-bg); border-color: var(--border-color); }
      .thread-view-header { background-color: var(--header-bg); border: 1px solid var(--border-color); margin-bottom: 15px; padding: 10px; text-align: center; font-size: 1.1em; font-weight: bold; color: var(--text-color); }
      .thread-view-header a { color: var(--accent-red); }
      .thread-view-header a:hover { color: var(--link-hover); }
      :target { scroll-margin-top: 70px; }
      .post.highlighted, .reply.highlighted { background-color: #404050 !important; border-color: var(--link-color) !important; transition: background-color 0.3s ease, border-color 0.3s ease; }
      #post-form h4, .reply-form-container h4 { margin: 0 0 10px 0; color: var(--accent-blue); }
      .action-form .post-preview { background-color: var(--post-bg); border: 1px dashed var(--border-color); padding: 10px; margin-bottom: 15px; font-size: 0.9em; max-height: 100px; overflow: auto; }

      /* Responsive adjustments */
      @media (max-width: 767px) {
        body { font-size: 11pt; }
        .container { padding: 0 10px; }
        header h1 { font-size: 1.5em; }
        .channel-nav-content { font-size: 0.9em; gap: 4px 8px; }
        .board-index-list { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
        .post-form th, .reply-form-container th, .action-form th { width: auto; text-align: left; display: block; padding-bottom: 2px; padding-right: 6px; }
        .post-form td, .reply-form-container td, .action-form td { display: block; padding-top: 0; }
        .post-form input[type="text"], .post-form input[type="password"], .post-form textarea, .post-form select,
        .reply-form-container input[type="text"], .reply-form-container input[type="password"], .reply-form-container textarea,
        .action-form input[type="text"], .action-form input[type="password"], .action-form textarea { width: calc(100% - 12px); padding: 6px; }
        .post-form input[type="submit"], .reply-form-container input[type="submit"], .action-form input[type="submit"] { display: block; width: auto; margin-top: 10px; }
        .file-info { flex-direction: column; align-items: stretch; gap: 5px 0; }
        .file-info .media-toggle { margin-bottom: 5px; }
        .file-info .file-details { margin-top: 0; font-size: 1em; }
        .reply-container { margin-left: 0; }
        .reply, .omitted-posts, .reply-form-container { margin-left: 5px; margin-right: 5px; max-width: calc(100% - 10px); min-width: auto; }
        .post-info { font-size: 0.9em; }
        .post-info .name { display: block; margin-bottom: 3px; }
        .post-info .time, .post-info .post-id, .post-info .reply-link, .post-info .action-link, .post-info .reply-count { font-size: 0.95em; margin-left: 4px; display: inline-block; margin-bottom: 3px; margin-right: 5px; }
        .post-info .time:first-of-type { margin-left: 0; }
        .pagination { font-size: 1em; }
        .pagination a, .pagination span { padding: 3px 6px; }
        .thread-view-header { font-size: 1em; }
        :target { scroll-margin-top: 60px; }
      }
      @media (min-width: 768px) {
        .post-form th, .action-form th { width: 130px; text-align: right; display: table-cell; }
        .post-form td, .action-form td { display: table-cell; }
        .reply-form-container th { width: 110px; }
        .file-info { flex-direction: row; align-items: flex-start; gap: 5px 10px; }
        .file-info .media-toggle { margin-bottom: 0; }
        .file-info .file-details { margin-top: 0; }
        .reply-container { margin-left: 20px; }
        .reply, .omitted-posts, .reply-form-container { margin-left: 20px; margin-right: 0; max-width: calc(100% - 20px); }
        .post-info .name { display: inline-block; margin-bottom: 0; }
        .post-info .time, .post-info .post-id, .post-info .reply-link, .post-info .action-link, .post-info .reply-count { font-size: 0.9em; margin-left: 8px; display: inline; margin-bottom: 0; margin-right: 0; }
      }
      .flex-container { display: flex; justify-content: center; }
      .flex-container img { max-width: 100%; height: 250px; }
    </style>
    <script>
      // Pass current channel code to JavaScript if on a channel page
      <?php if (!$show_board_index && $current_channel_code) : ?>
        const currentChannel = "<?php echo htmlspecialchars($current_channel_code); ?>";
      <?php else : ?>
        const currentChannel = null; // Not on a channel page
      <?php endif; ?>
    </script>
    <script>
      // --- Standard JS (toggleReplyForm, toggleMedia, toggleFullText) ---
      const IMAGE_TYPES = ['image'];
      const VIDEO_TYPES = ['video'];
      const AUDIO_TYPES = ['audio'];
      const YOUTUBE_TYPE = 'youtube';

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
        }
      }

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

        if (IMAGE_TYPES.includes(mediaType)) {
          viewButtonText = 'View Image'; hideButtonText = 'Hide Image';
        } else if (VIDEO_TYPES.includes(mediaType)) {
          viewButtonText = 'View Video'; hideButtonText = 'Hide Video';
        } else if (AUDIO_TYPES.includes(mediaType)) {
          viewButtonText = 'View Audio'; hideButtonText = 'Hide Audio';
        } else if (mediaType === YOUTUBE_TYPE) {
          viewButtonText = 'View YouTube'; hideButtonText = 'Hide YouTube';
        }

        if (isHidden) {
          mediaContainer.style.display = 'block';
          button.textContent = hideButtonText;

          const loadedUrl = mediaContainer.dataset.loadedUrl;
          const mediaElementExists = mediaContainer.querySelector('video, audio, iframe, img');
          const needsLoad = !loadedUrl || loadedUrl !== mediaUrl || !mediaElementExists;

          if (needsLoad) {
            mediaContainer.innerHTML = '<span>Loading...</span>'; // Placeholder
            mediaContainer.dataset.loadedUrl = mediaUrl; // Store the URL that was loaded

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
              mediaContainer.innerHTML = ''; // Clear placeholder
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
              mediaContainer.innerHTML = ''; // Clear placeholder
              mediaContainer.appendChild(embedContainer);

            } else if (AUDIO_TYPES.includes(mediaType)) {
              mediaElement = document.createElement('audio');
              mediaElement.src = mediaUrl;
              mediaElement.controls = true;
              mediaElement.preload = 'metadata';
              mediaContainer.innerHTML = ''; // Clear placeholder
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
                mediaContainer.innerHTML = ''; // Clear placeholder
                mediaContainer.appendChild(embedContainer);
              } else {
                mediaContainer.innerHTML = '<span class="error">Failed to embed YouTube video (Invalid URL).</span>';
              }
            } else {
              mediaContainer.innerHTML = '<span class="error">Unsupported media type: ' + mediaType + '</span>';
            }

            if (mediaElement && (mediaElement.tagName === 'VIDEO' || mediaElement.tagName === 'AUDIO' || mediaElement.tagName === 'IMG' || mediaElement.tagName === 'IFRAME')) {
              mediaElement.onerror = function(e) {
                console.error('Media loading failed:', this.src || this.dataset.mediaUrl, e); // Corrected data attribute access
                if (!mediaContainer.querySelector('.media-error-message')) {
                  const errorSpan = document.createElement('span');
                  errorSpan.classList.add('error', 'media-error-message');
                  errorSpan.textContent = 'Failed to load media. Check the file format, URL, or server configuration.';
                  mediaContainer.innerHTML = '';
                  mediaContainer.appendChild(errorSpan);
                }
              };
            }
          } // end if (needsLoad)
        } else {
          // Hide media
          mediaContainer.style.display = 'none';
          button.textContent = viewButtonText;

          mediaContainer.querySelectorAll('video, audio, iframe').forEach(mediaElement => {
            if ((mediaElement.tagName === 'VIDEO' || mediaElement.tagName === 'AUDIO') && typeof mediaElement.pause === 'function') {
              mediaElement.pause();
              mediaElement.src = ''; // Stop loading/buffering
            } else if (mediaElement.tagName === 'IFRAME') { // Stop iframe loading too
              mediaElement.src = 'about:blank';
            }
          });
          mediaContainer.innerHTML = ''; // Clear content fully
          delete mediaContainer.dataset.loadedUrl;
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

      document.addEventListener('DOMContentLoaded', function() {
        // --- Event Delegation for Clicks ---
        document.body.addEventListener('click', function(event) {
          // Media toggle button
          if (event.target.matches('.show-media-btn')) {
            toggleMedia(event.target);
          }
          // Show full text button
          else if (event.target.matches('.show-full-text-btn')) {
            const fullTextId = event.target.dataset.targetId;
            if (fullTextId) {
              toggleFullText(event.target, fullTextId);
            }
          }
          // NSFW warning close button
          else if (event.target.matches('#nsfw-warning-close')) {
            const nsfwWarning = document.getElementById('nsfw-warning');
            if (nsfwWarning) {
              nsfwWarning.style.display = 'none';
            }
          }
          // Quick reply link
          else if (event.target.matches('.reply-link[href^="#reply-form-"]')) {
            event.preventDefault();
            const hrefAttr = event.target.getAttribute('href');
            if (hrefAttr) {
              const threadIdMatch = hrefAttr.match(/#reply-form-(\d+)/);
              if (threadIdMatch && threadIdMatch[1]) {
                toggleReplyForm(threadIdMatch[1]);
              }
            }
          }
          // New Thread Form Toggle Button
          else if (event.target.matches('#togglePostFormButton')) {
            togglePostForm();
          }
          // Note: Edit/Delete links now go to new pages/forms, so no JS needed here for them.
        });

        // --- Post highlighting logic ---
        let highlightTimeout = null;
        function highlightPost(targetPost, addClass) {
          if (!targetPost) return;
          clearTimeout(highlightTimeout);
          if (addClass) {
            targetPost.classList.add('highlighted');
            highlightTimeout = setTimeout(() => targetPost.classList.remove('highlighted'), 1500);
          } else {
            targetPost.classList.remove('highlighted');
          }
        }
        document.body.addEventListener('mouseover', function(event) {
          const link = event.target.closest('.reply-mention');
          if (link && link.getAttribute('href')?.startsWith('#post-')) {
            const targetId = link.getAttribute('href').substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            highlightPost(targetPost, true);
          }
        });
        document.body.addEventListener('mouseout', function(event) {
          const link = event.target.closest('.reply-mention');
          if (link && link.getAttribute('href')?.startsWith('#post-')) {
            const targetId = link.getAttribute('href').substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            highlightPost(targetPost, false);
          }
        });
        document.body.addEventListener('click', function(event) {
          const link = event.target.closest('.reply-mention');
          if (link && link.getAttribute('href').startsWith('#post-')) {
            // Don't prevent default navigation, just highlight
            const targetId = link.getAttribute('href').substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            // Highlight slightly longer on click
            if (targetPost) {
              clearTimeout(highlightTimeout);
              targetPost.classList.add('highlighted');
              highlightTimeout = setTimeout(() => targetPost.classList.remove('highlighted'), 2500);
            }
          }
        });
        // Highlight on page load if hash matches
        if (window.location.hash && window.location.hash.startsWith('#post-')) {
          const targetId = window.location.hash.substring(1);
          // Use requestAnimationFrame to ensure layout is complete before highlighting/scrolling
          requestAnimationFrame(() => {
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            if (targetPost) {
              highlightPost(targetPost, true);
              // Optional: smooth scroll into view if needed, accounting for fixed header space
              // targetPost.scrollIntoView({ behavior: 'smooth', block: 'start' }); // Adjust block as needed
            }
          });
        }


        // --- New Thread Form Collapse Logic ---
        const postFormContent = document.getElementById('postFormContent');
        const toggleButton = document.getElementById('togglePostFormButton');

        // Ensure the toggle function is globally accessible if the button exists
        if (toggleButton) {
          window.togglePostForm = function() {
            if (!postFormContent) return; // Safety check

            const isCollapsed = postFormContent.style.display === 'none' || postFormContent.style.display === '';
            const newState = isCollapsed ? 'expanded' : 'collapsed';

            // Apply visual state
            if (newState === 'expanded') {
              postFormContent.style.display = 'block';
              toggleButton.textContent = 'Hide Form';
            } else {
              postFormContent.style.display = 'none';
              toggleButton.textContent = 'Show Form';
            }

            // Save state if on a channel page
            if (typeof currentChannel === 'string' && currentChannel && postFormContent) {
              const stateKey = 'postFormState_channel_' + currentChannel;
              try {
                localStorage.setItem(stateKey, newState);
              } catch (e) {
                console.error("Failed to save post form state to Local Storage:", e);
              }
            }
          }

          // Apply initial state from localStorage if applicable
          if (typeof currentChannel === 'string' && currentChannel && postFormContent) {
            const stateKey = 'postFormState_channel_' + currentChannel;
            let savedState = 'collapsed'; // Default
            try {
              savedState = localStorage.getItem(stateKey) || 'collapsed';
            } catch (e) {
              console.error("Failed to read post form state from Local Storage:", e);
            }

            // Apply the initial state without calling the full toggle function
            if (savedState === 'expanded') {
              postFormContent.style.display = 'block';
              toggleButton.textContent = 'Hide Form';
            } else {
              postFormContent.style.display = 'none';
              toggleButton.textContent = 'Show Form';
            }
          } else if (postFormContent) {
            // Default state if not on a channel page or local storage blocked
            postFormContent.style.display = 'none';
            toggleButton.textContent = 'Show Form';
          }

        } // end if (toggleButton)

      });
    </script>
  </head>
  <body>
    <div class="container">
      <header>
        <h1><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code ?? '...') . '/ - ' . htmlspecialchars($current_channel_display_name ?? '...') . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></h1>
        <div class="flex-container">
          <img src="/HDBoard.png" alt="HDBoard Image" style="max-width: 100%; height: 250px; margin: 0 auto; display: block;">
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
                  <?php else : error_log("Warning: Channel code '{$channel_code_nav}' in category '{$category_name}' is not defined in CHANNEL_NAMES."); ?>
                  <?php endif; ?>
                <?php endforeach; ?>
              <?php endforeach; ?>
              <?php
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
              </div> <!-- /.channel-nav-content -->
          <?php if (!$show_board_index && $current_channel_code) : ?>
            </details> <!-- /.channel-nav-collapsible -->
          <?php endif; ?>
        </nav>
      </header>

      <?php // --- Display Global Messages (Action/Post Errors/Success) --- ?>
      <?php if ($post_error) : ?>
        <p class="error"><?php echo htmlspecialchars($post_error); ?></p>
      <?php endif; ?>
      <?php if ($post_success) : // Less likely used due to redirects ?>
        <p class="success"><?php echo htmlspecialchars($post_success); ?></p>
      <?php endif; ?>
      <?php if ($action_error) : ?>
        <p class="error"><?php echo htmlspecialchars($action_error); ?></p>
      <?php endif; ?>
      <?php if ($action_success) : // May be shown briefly before redirect, or if no redirect occurs ?>
        <p class="success"><?php echo htmlspecialchars($action_success); ?></p>
      <?php endif; ?>

      <?php // --- Display Action Forms (Edit/Delete Confirmation/Fields) --- ?>
      <?php if ($show_action_form && $post_data_for_form) : ?>
        <?php
        // Type should be explicitly set in the $post_data_for_form array where needed now
        $form_post_type = $post_data_for_form['type'] ?? null;
        $form_post_id = $post_data_for_form['id'] ?? null;
        $form_username = $post_data_for_form['username'] ?? 'Unknown User';
        $form_comment_preview = isset($post_data_for_form['comment']) ? htmlspecialchars(mb_substr($post_data_for_form['comment'], 0, 100)) . (mb_strlen($post_data_for_form['comment']) > 100 ? '...' : '') : '[No Comment Data]';
        ?>
        <?php if ($form_post_type && $form_post_id) : // Only show form if basic data is present ?>
          <div class="action-form">
            <?php if ($show_action_form === 'delete_confirm') : ?>
              <h3>Confirm Deletion</h3>
              <p>Please enter the password for user '<strong><?php echo htmlspecialchars($form_username); ?></strong>' to delete this <?php echo htmlspecialchars($form_post_type); ?> (ID: <?php echo $form_post_id; ?>).</p>
              <div class="post-preview"><strong>Comment starts:</strong> <?php echo $form_comment_preview; ?></div>
              <form action="./" method="post">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <tr>
                    <th><label for="password_del">Password</label></th>
                    <td><input type="password" name="password" id="password_del" required></td>
                  </tr>
                  <tr>
                    <th></th>
                    <td><input type="submit" value="Delete <?php echo ucfirst(htmlspecialchars($form_post_type)); ?>"></td>
                  </tr>
                </table>
              </form>

            <?php elseif ($show_action_form === 'edit_confirm') : ?>
              <h3>Verify Ownership to Edit</h3>
              <p>Please enter the password for user '<strong><?php echo htmlspecialchars($form_username); ?></strong>' to edit this <?php echo htmlspecialchars($form_post_type); ?> (ID: <?php echo $form_post_id; ?>).</p>
              <div class="post-preview"><strong>Comment starts:</strong> <?php echo $form_comment_preview; ?></div>
              <form action="./" method="post">
                <input type="hidden" name="action" value="edit">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <tr>
                    <th><label for="password_edit_ver">Password</label></th>
                    <td><input type="password" name="password" id="password_edit_ver" required></td>
                  </tr>
                  <tr>
                    <th></th>
                    <td><input type="submit" value="Verify and Edit"></td>
                  </tr>
                </table>
              </form>

            <?php elseif ($show_action_form === 'edit_fields') : ?>
              <h3>Edit <?php echo ucfirst(htmlspecialchars($form_post_type)); ?></h3>
              <p>Editing <?php echo htmlspecialchars($form_post_type); ?> ID: <?php echo $form_post_id; ?> by <?php echo htmlspecialchars($form_username); ?></p>
              <form action="./" method="post">
                <input type="hidden" name="action" value="save_edit">
                <input type="hidden" name="type" value="<?php echo htmlspecialchars($form_post_type); ?>">
                <input type="hidden" name="id" value="<?php echo $form_post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <?php if ($form_post_type === 'thread') : ?>
                  <tr>
                    <th><label for="subject_edit">Subject</label></th>
                    <td><input type="text" name="subject" id="subject_edit" value="<?php echo htmlspecialchars($post_data_for_form['subject_attempt'] ?? $post_data_for_form['subject'] ?? ''); ?>" size="30"></td>
                  </tr>
                  <?php endif; ?>
                  <tr>
                    <th><label for="comment_edit">Comment</label></th>
                    <td><textarea name="comment" id="comment_edit" rows="5" cols="50" required><?php echo htmlspecialchars($post_data_for_form['comment_attempt'] ?? $post_data_for_form['comment'] ?? ''); ?></textarea></td>
                  </tr>
                  <tr>
                    <th></th>
                    <td><input type="submit" value="Save Changes"></td>
                  </tr>
                </table>
              </form>
            <?php endif; ?>
          </div>
          <hr> <?php // Separator after the action form ?>
        <?php else : ?>
          <p class="error">Could not display action form due to missing data.</p>
        <?php endif; // End basic data check ?>
      <?php endif; // End action form display ?>


      <?php // --- Main Content Display (Board Index or Channel/Thread View) --- ?>
      <?php // Only show main content if an action form isn't displayed, or if action resulted in non-form error ?>
      <?php if (empty($show_action_form) || (!empty($action_error) && !in_array($show_action_form, ['delete_confirm', 'edit_confirm', 'edit_fields']))) : ?>

        <?php if ($show_board_index) : // --- Board Index View --- ?>
          <h2>Available Boards</h2>
          <ul class="board-index-list">
            <?php foreach ($board_index_data as $board) : ?>
              <li>
                <a href="./?channel=<?php echo urlencode($board['code']); ?>">
                  <span class="board-code">/<?php echo htmlspecialchars($board['code']); ?>/</span>
                  <span class="board-name"><?php echo htmlspecialchars($board['name']); ?></span>
                  <span class="board-post-count">(<?php echo number_format($board['total_posts']); ?> posts)</span>
                </a>
              </li>
            <?php endforeach; ?>
            <?php if (empty($board_index_data)) : ?>
              <p style="grid-column: 1 / -1; text-align: center; color: #aaa;">No boards found or configured.</p>
            <?php endif; ?>
          </ul>
          <hr>
          <p style="text-align: center; color: #aaa;">Select a board to view content.</p>

        <?php elseif ($current_channel_code) : // --- Channel or Thread View --- ?>
          <?php if (!$viewing_thread_id && in_array($current_channel_code, NSFW_CHANNELS)) : ?>
            <div class="nsfw-warning" id="nsfw-warning">
              <strong>Warning:</strong> Content on /<?php echo htmlspecialchars($current_channel_code); ?>/ (<?php echo htmlspecialchars($current_channel_display_name); ?>) may be NSFW. Proceed with caution.
              <button class="nsfw-warning-close" id="nsfw-warning-close" title="Close Warning" aria-label="Close Warning">×</button>
            </div>
          <?php endif; ?>

          <?php if ($viewing_thread_id && $thread_op) : // --- Thread View --- ?>
            <div class="thread-view-header">
              [<a href="./?channel=<?php echo urlencode($current_channel_code); ?>">Return to /<?php echo htmlspecialchars($current_channel_code); ?>/ - <?php echo htmlspecialchars($current_channel_display_name); ?></a>]
            </div>
            <div class="reply-form-container">
              <h4>Reply to Thread No.<?php echo $viewing_thread_id; ?></h4>
              <form action="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $viewing_thread_id; ?>" method="post" enctype="multipart/form-data">
                <input type="hidden" name="thread_id" value="<?php echo $viewing_thread_id; ?>">
                <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <table>
                  <tr>
                    <th><label for="reply_username">Username</label></th>
                    <td><input type="text" name="username" id="reply_username" size="30" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td>
                  </tr>
                  <tr>
                    <th><label for="reply_password">Password</label></th>
                    <td><input type="password" name="password" id="reply_password" size="30"> <small>(Required if username registered)</small></td>
                  </tr>
                  <tr>
                    <th><label for="reply_comment">Comment</label></th>
                    <td><textarea name="comment" id="reply_comment" rows="4" cols="45" required></textarea></td>
                  </tr>
                  <tr>
                    <th><label for="reply_image">File</label></th>
                    <td><input type="file" name="image" id="reply_image" accept=".<?php echo implode(',.', ALLOWED_EXTENSIONS); ?>,video/*,audio/*,image/*"></td>
                  </tr>
                  <tr>
                    <th></th>
                    <td><input type="submit" value="Submit Reply"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td>
                  </tr>
                </table>
              </form>
            </div>
            <hr>
            <?php
            // Render the Thread OP
            $thread = $threads[0]; // In thread view, $threads contains only the OP
            $thread_id = $thread['id'];
            $post_element_id = 'post-' . $thread_id;
            $post_media_html = '';
            $display_name = (!empty($thread['username'])) ? htmlspecialchars($thread['username']) : 'Anonymous';

            // 1. Uploaded File for OP
            if ($thread['image']) {
              $uploaded_media_relative_path = $thread['image'];
              // Basic sanitation for URL path construction
              $safe_relative_path = str_replace(['../', './'], '', $uploaded_media_relative_path);
              $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($safe_relative_path, ENT_QUOTES, 'UTF-8');
              $uploaded_media_local_path = UPLOADS_DIR . '/' . $uploaded_media_relative_path; // Use original for local check
              $orig_name = htmlspecialchars($thread['image_orig_name'] ?? basename($thread['image']));
              $img_w = $thread['image_w'] ?? '?';
              $img_h = $thread['image_h'] ?? '?';
              $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
              $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
              $uploaded_media_type = get_render_media_type($uploaded_media_relative_path);
              $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
              $media_item_id = $post_element_id . '-uploaded';
              $post_media_html .= "<div class='file-info uploaded-file-info'><div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_item_id}' data-media-url='{$uploaded_media_url}' data-media-type='{$uploaded_media_type}'>{$view_button_text}</button></div><span class='file-details'>File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")</span></div><div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
            }
            // 2. Comment Links for OP
            $comment_raw_from_db = $thread['comment'];
            $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
            $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
            $post_media_html .= $link_media_result['media_html'];
            // 3. Format Comment
            $formatted_comment = format_comment($cleaned_comment_for_formatting);
            ?>
            <div class="thread" id="thread-<?php echo $thread_id; ?>">
              <div class="post op" id="<?php echo $post_element_id; ?>">
                <p class="post-info">
                  <?php if (!empty($thread['subject'])) : ?>
                    <span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span>
                  <?php endif; ?>
                  <span class="name"><?php echo $display_name; ?></span>
                  <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                  <span class="post-id">No.<?php echo $thread_id; ?></span>
                  <a href="#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                  <?php // Edit/Delete links for OP ?>
                  <?php if (!empty($thread['username'])) : ?>
                    <span class="action-link">[<a href="./?action=confirm_delete&type=thread&id=<?php echo $thread_id; ?>" title="Delete Thread">Delete</a>]</span>
                    <span class="action-link">[<a href="./?action=show_edit_form&type=thread&id=<?php echo $thread_id; ?>" title="Edit Thread">Edit</a>]</span>
                  <?php endif; ?>
                </p>
                <?php echo $post_media_html; ?>
                <div class="comment"><?php echo $formatted_comment; ?></div>
              </div><!-- /.post.op -->

              <div class="reply-container">
                <?php // Render Replies ?>
                <?php $all_thread_replies = $replies_to_display[$thread_id] ?? []; ?>
                <?php foreach ($all_thread_replies as $reply) : ?>
                  <?php
                  $reply_id = $reply['id'];
                  $post_element_id = 'post-' . $reply_id;
                  $reply_media_html = '';
                  $display_name_reply = (!empty($reply['username'])) ? htmlspecialchars($reply['username']) : 'Anonymous';

                  // 1. Uploaded File for Reply
                  if ($reply['image']) {
                    $uploaded_media_relative_path = $reply['image'];
                    // Basic sanitation for URL path construction
                    $safe_relative_path = str_replace(['../', './'], '', $uploaded_media_relative_path);
                    $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($safe_relative_path, ENT_QUOTES, 'UTF-8');
                    $uploaded_media_local_path = UPLOADS_DIR . '/' . $uploaded_media_relative_path; // Use original for local check
                    $orig_name = htmlspecialchars($reply['image_orig_name'] ?? basename($reply['image']));
                    $img_w = $reply['image_w'] ?? '?';
                    $img_h = $reply['image_h'] ?? '?';
                    $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
                    $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                    $uploaded_media_type = get_render_media_type($uploaded_media_relative_path);
                    $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
                    $media_item_id = $post_element_id . '-uploaded';
                    $reply_media_html .= "<div class='file-info uploaded-file-info'><div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_item_id}' data-media-url='{$uploaded_media_url}' data-media-type='{$uploaded_media_type}'>{$view_button_text}</button></div><span class='file-details'>File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")</span></div><div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
                  }
                  // 2. Comment Links for Reply
                  $comment_raw_from_db = $reply['comment'];
                  $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
                  $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
                  $reply_media_html .= $link_media_result['media_html'];
                  // 3. Format Reply Comment
                  $formatted_comment = format_comment($cleaned_comment_for_formatting);
                  ?>
                  <div class="reply" id="<?php echo $post_element_id; ?>">
                    <p class="post-info">
                      <span class="name"><?php echo $display_name_reply; ?></span>
                      <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                      <span class="post-id">No.<?php echo $reply_id; ?></span>
                      <a href="#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                      <?php // Edit/Delete links for Reply ?>
                      <?php if (!empty($reply['username'])) : ?>
                        <span class="action-link">[<a href="./?action=confirm_delete&type=reply&id=<?php echo $reply_id; ?>" title="Delete Reply">Delete</a>]</span>
                        <span class="action-link">[<a href="./?action=show_edit_form&type=reply&id=<?php echo $reply_id; ?>" title="Edit Reply">Edit</a>]</span>
                      <?php endif; ?>
                    </p>
                    <?php echo $reply_media_html; ?>
                    <div class="comment"><?php echo $formatted_comment; ?></div>
                  </div><!-- /.reply -->
                <?php endforeach; ?>
                <?php if (empty($all_thread_replies)) : ?>
                  <p style="text-align: center; color: #aaa; margin-top: 15px;">No replies yet.</p>
                <?php endif; ?>
              </div><!-- /.reply-container -->
            </div><!-- /.thread -->
            <hr>

          <?php else : // --- Board View --- ?>
            <div class="post-form" id="post-form">
              <h2>Post a new thread in /<?php echo htmlspecialchars($current_channel_code); ?>/ - <?php echo htmlspecialchars($current_channel_display_name); ?></h2>
              <button id="togglePostFormButton" class="toggle-button" type="button">Show Form</button>
              <div id="postFormContent" class="post-form-content" style="display: none;">
                <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                  <input type="hidden" name="form_type" value="new_thread">
                  <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                  <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                  <table>
                    <tr>
                      <th><label for="username">Username</label></th>
                      <td><input type="text" name="username" id="username" size="30" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td>
                    </tr>
                    <tr>
                      <th><label for="password">Password</label></th>
                      <td><input type="password" name="password" id="password" size="30"> <small>(Required to register username)</small></td>
                    </tr>
                    <tr>
                      <th><label for="subject">Subject</label></th>
                      <td><input type="text" name="subject" id="subject" size="30"></td>
                    </tr>
                    <tr>
                      <th><label for="comment">Post</label></th>
                      <td><textarea name="comment" id="comment" rows="5" cols="50" required></textarea></td>
                    </tr>
                    <tr>
                      <th><label for="image">File</label></th>
                      <td><input type="file" name="image" id="image" accept=".<?php echo implode(',.', ALLOWED_EXTENSIONS); ?>,video/*,audio/*,image/*"></td>
                    </tr>
                    <tr>
                      <th></th>
                      <td><input type="submit" value="Submit Thread"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td>
                    </tr>
                  </table>
                </form>
              </div>
            </div>
            <hr>
            <?php if ($total_threads == 0) : ?>
              <p style="text-align: center; color: #aaa; margin-top: 30px;">No threads in /<?php echo htmlspecialchars($current_channel_code); ?>/ (<?php echo htmlspecialchars($current_channel_display_name); ?>) yet. Be the first!</p>
            <?php else : ?>
              <div class="pagination">
                <?php if ($current_page > 1) : ?> <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a> <?php else : ?> <span class="disabled"><< Prev</span> <?php endif; ?>
                <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
                <?php if ($current_page < $total_pages) : ?> <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a> <?php else : ?> <span class="disabled">Next >></span> <?php endif; ?>
              </div>
              <hr>
              <?php // Render Threads for Board View ?>
              <?php foreach ($threads as $thread) : ?>
                <?php
                $thread_id = $thread['id'];
                $post_element_id = 'post-' . $thread_id;
                $thread_replies_preview = $replies_to_display[$thread_id] ?? [];
                $total_reply_count = $reply_counts[$thread_id] ?? 0;
                $omitted_count = max(0, $total_reply_count - count($thread_replies_preview));
                $display_name_thread = (!empty($thread['username'])) ? htmlspecialchars($thread['username']) : 'Anonymous';
                $thread_media_html = '';
                $comment_raw_from_db = $thread['comment'];

                // 1. Uploaded File for OP (Board View)
                if ($thread['image']) {
                  $uploaded_media_relative_path = $thread['image'];
                  // Basic sanitation for URL path construction
                  $safe_relative_path = str_replace(['../', './'], '', $uploaded_media_relative_path);
                  $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($safe_relative_path, ENT_QUOTES, 'UTF-8');
                  $uploaded_media_local_path = UPLOADS_DIR . '/' . $uploaded_media_relative_path; // Use original for local check
                  $orig_name = htmlspecialchars($thread['image_orig_name'] ?? basename($thread['image']));
                  $img_w = $thread['image_w'] ?? '?';
                  $img_h = $thread['image_h'] ?? '?';
                  $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
                  $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                  $uploaded_media_type = get_render_media_type($uploaded_media_relative_path);
                  $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
                  $media_item_id = $post_element_id . '-uploaded';
                  $thread_media_html .= "<div class='file-info uploaded-file-info'><div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_item_id}' data-media-url='{$uploaded_media_url}' data-media-type='{$uploaded_media_type}'>{$view_button_text}</button></div><span class='file-details'>File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")</span></div><div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
                }
                // 2. Comment Links for OP (Board View)
                $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
                $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
                $thread_media_html .= $link_media_result['media_html'];
                // 3. Format & Truncate Comment
                $formatted_comment = format_comment($cleaned_comment_for_formatting);
                $display_comment_html = '';
                $full_comment_id = 'full-comment-' . $post_element_id;
                if (mb_strlen(strip_tags($comment_raw_from_db)) > COMMENT_PREVIEW_LENGTH) { // Check length of raw text before formatting for truncation decision
                  // Find a suitable break point near the limit
                  $truncated_cleaned_comment = mb_substr($cleaned_comment_for_formatting, 0, COMMENT_PREVIEW_LENGTH);
                  // Ensure we don't cut mid-word (optional refinement)
                  $last_space = mb_strrpos($truncated_cleaned_comment, ' ');
                  if ($last_space !== false && $last_space > COMMENT_PREVIEW_LENGTH - 50) { // Only trim if space is near the end
                    $truncated_cleaned_comment = mb_substr($truncated_cleaned_comment, 0, $last_space);
                  }
                  $truncated_formatted_comment = format_comment($truncated_cleaned_comment); // Format the truncated part
                  $display_comment_html = "<div class='comment-truncated'>{$truncated_formatted_comment}... <br><button class='show-full-text-btn' data-target-id='{$full_comment_id}'>View Full Text</button></div><div id='{$full_comment_id}' class='comment-full'>{$formatted_comment}</div>";
                } else {
                  $display_comment_html = $formatted_comment;
                }
                ?>
                <div class="thread" id="thread-<?php echo $thread_id; ?>">
                  <div class="post op" id="<?php echo $post_element_id; ?>">
                    <p class="post-info">
                      <?php if (!empty($thread['subject'])) : ?> <span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span> <?php endif; ?>
                      <span class="name"><?php echo $display_name_thread; ?></span>
                      <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                      <span class="post-id">No.<?php echo $thread_id; ?></span>
                      <span class="reply-link">[<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>" title="View Thread">View</a>]</span>
                      <span class="reply-link">[<a href="#reply-form-<?php echo $thread_id; ?>" title="Quick Reply">Reply</a>]</span> <?php /* Keep JS toggle for quick reply */ ?>
                      <?php if ($total_reply_count > 0) : ?> <span class="reply-count">(<?php echo $total_reply_count; ?> replies)</span> <?php endif; ?>
                      <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                      <?php // Edit/Delete links for OP in Board View ?>
                      <?php if (!empty($thread['username'])) : ?>
                        <span class="action-link">[<a href="./?action=confirm_delete&type=thread&id=<?php echo $thread_id; ?>" title="Delete Thread">Delete</a>]</span>
                        <span class="action-link">[<a href="./?action=show_edit_form&type=thread&id=<?php echo $thread_id; ?>" title="Edit Thread">Edit</a>]</span>
                      <?php endif; ?>
                    </p>
                    <?php echo $thread_media_html; ?>
                    <div class="comment"><?php echo $display_comment_html; ?></div>
                  </div><!-- /.post.op -->

                  <div class="reply-form-container" id="reply-form-<?php echo $thread_id; ?>" style="display: none;">
                    <h4>Reply to Thread No.<?php echo $thread_id; ?></h4>
                    <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                      <input type="hidden" name="thread_id" value="<?php echo $thread_id; ?>">
                      <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                      <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                      <table>
                        <tr>
                          <th><label for="reply_username_q_<?php echo $thread_id; ?>">Username</label></th>
                          <td><input type="text" name="username" id="reply_username_q_<?php echo $thread_id; ?>" size="30" maxlength="<?php echo USERNAME_MAX_LENGTH; ?>"> <small>(Optional)</small></td>
                        </tr>
                        <tr>
                          <th><label for="reply_password_q_<?php echo $thread_id; ?>">Password</label></th>
                          <td><input type="password" name="password" id="reply_password_q_<?php echo $thread_id; ?>" size="30"> <small>(Required if username registered)</small></td>
                        </tr>
                        <tr>
                          <th><label for="reply_comment_<?php echo $thread_id; ?>">Comment</label></th>
                          <td><textarea name="comment" id="reply_comment_<?php echo $thread_id; ?>" rows="4" cols="45" required></textarea></td>
                        </tr>
                        <tr>
                          <th><label for="reply_image_<?php echo $thread_id; ?>">File</label></th>
                          <td><input type="file" name="image" id="reply_image_<?php echo $thread_id; ?>" accept=".<?php echo implode(',.', ALLOWED_EXTENSIONS); ?>,video/*,audio/*,image/*"></td>
                        </tr>
                        <tr>
                          <th></th>
                          <td><input type="submit" value="Submit Reply"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td>
                        </tr>
                      </table>
                    </form>
                  </div><!-- /.reply-form-container -->

                  <div class="reply-container">
                    <?php if ($omitted_count > 0) : ?>
                      <p class="omitted-posts"><?php echo $omitted_count; ?> replies omitted. [<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>">Click here to view the full thread.</a>]</p>
                    <?php endif; ?>
                    <?php // Render Reply Previews ?>
                    <?php foreach ($thread_replies_preview as $reply) : ?>
                      <?php
                      $reply_id = $reply['id'];
                      $post_element_id = 'post-' . $reply_id;
                      $reply_media_html = '';
                      $comment_raw_from_db = $reply['comment'];
                      $display_name_reply_preview = (!empty($reply['username'])) ? htmlspecialchars($reply['username']) : 'Anonymous';

                      // 1. Uploaded File for Reply Preview
                      if ($reply['image']) {
                        $uploaded_media_relative_path = $reply['image'];
                        // Basic sanitation for URL path construction
                        $safe_relative_path = str_replace(['../', './'], '', $uploaded_media_relative_path);
                        $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($safe_relative_path, ENT_QUOTES, 'UTF-8');
                        $uploaded_media_local_path = UPLOADS_DIR . '/' . $uploaded_media_relative_path; // Use original for local check
                        $orig_name = htmlspecialchars($reply['image_orig_name'] ?? basename($reply['image']));
                        $img_w = $reply['image_w'] ?? '?';
                        $img_h = $reply['image_h'] ?? '?';
                        $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
                        $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                        $uploaded_media_type = get_render_media_type($uploaded_media_relative_path);
                        $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
                        $media_item_id = $post_element_id . '-uploaded';
                        $reply_media_html .= "<div class='file-info uploaded-file-info'><div class='media-toggle'><button class='show-media-btn' data-media-id='{$media_item_id}' data-media-url='{$uploaded_media_url}' data-media-type='{$uploaded_media_type}'>{$view_button_text}</button></div><span class='file-details'>File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")</span></div><div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
                      }
                      // 2. Comment Links for Reply Preview
                      $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
                      $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
                      $reply_media_html .= $link_media_result['media_html'];
                      // 3. Format & Truncate Reply Preview Comment
                      $formatted_comment = format_comment($cleaned_comment_for_formatting);
                      $display_comment_html = '';
                      $full_comment_id_reply = 'full-comment-' . $post_element_id;
                      if (mb_strlen(strip_tags($comment_raw_from_db)) > COMMENT_PREVIEW_LENGTH) { // Check length of raw text
                        $truncated_cleaned_comment = mb_substr($cleaned_comment_for_formatting, 0, COMMENT_PREVIEW_LENGTH);
                        $last_space = mb_strrpos($truncated_cleaned_comment, ' ');
                        if ($last_space !== false && $last_space > COMMENT_PREVIEW_LENGTH - 50) {
                          $truncated_cleaned_comment = mb_substr($truncated_cleaned_comment, 0, $last_space);
                        }
                        $truncated_formatted_comment = format_comment($truncated_cleaned_comment);
                        $display_comment_html = "<div class='comment-truncated'>{$truncated_formatted_comment}...<br><button class='show-full-text-btn' data-target-id='{$full_comment_id_reply}'>View Full Text</button></div><div id='{$full_comment_id_reply}' class='comment-full'>{$formatted_comment}</div>";
                      } else {
                        $display_comment_html = $formatted_comment;
                      }
                      ?>
                      <div class="reply" id="<?php echo $post_element_id; ?>">
                        <p class="post-info">
                          <span class="name"><?php echo $display_name_reply_preview; ?></span>
                          <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                          <span class="post-id">No.<?php echo $reply_id; ?></span>
                          <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                          <?php // Edit/Delete links for Reply Preview ?>
                          <?php if (!empty($reply['username'])) : ?>
                            <span class="action-link">[<a href="./?action=confirm_delete&type=reply&id=<?php echo $reply_id; ?>" title="Delete Reply">Delete</a>]</span>
                            <span class="action-link">[<a href="./?action=show_edit_form&type=reply&id=<?php echo $reply_id; ?>" title="Edit Reply">Edit</a>]</span>
                          <?php endif; ?>
                        </p>
                        <?php echo $reply_media_html; ?>
                        <div class="comment"><?php echo $display_comment_html; ?></div>
                      </div><!-- /.reply -->
                    <?php endforeach; ?>
                  </div><!-- /.reply-container -->
                </div><!-- /.thread -->
                <hr>
              <?php endforeach; ?>
              <div class="pagination">
                <?php if ($current_page > 1) : ?> <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a> <?php else : ?> <span class="disabled"><< Prev</span> <?php endif; ?>
                <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
                <?php if ($current_page < $total_pages) : ?> <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a> <?php else : ?> <span class="disabled">Next >></span> <?php endif; ?>
              </div>
            <?php endif; // End check for total_threads > 0 ?>
          <?php endif; // End board/thread view switch ?>
        <?php endif; // End check for current_channel_code exists ?>
      <?php endif; // End check for !show_action_form ?>

    </div> <!-- /.container -->
  </body>
</html>