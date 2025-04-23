<?php
// --- Configuration ---
define('DB_FILE', __DIR__ . '/board.db'); // Database file
define('UPLOADS_DIR', __DIR__ . '/uploads'); // Uploads directory
define('UPLOADS_URL_PATH', 'uploads'); // Relative web path
define('MAX_FILE_SIZE', 20 * 1024 * 1024); // 20 MB
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'webm', 'mp3', 'wav', 'ogg', 'avi', 'mov', 'flv', 'wmv']);
define('VIDEO_EXTENSIONS', ['mp4', 'webm', 'avi', 'mov', 'flv', 'wmv']);
define('AUDIO_EXTENSIONS', ['mp3', 'wav', 'ogg']);

// Define allowed channels using their short codes (used in URLs and DB)
define('ALLOWED_CHANNELS', [
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'gif', 'h', 'hr', 'k', 'm', 'o', 'p', 'r', 's', 't', 'u', 'v',
  'vg', 'vm', 'vmg', 'vr', 'vrpg', 'vst', 'w', 'wg', 'i', 'ic', 'r9k', 's4s', 'vip', 'qa', 'cm',
  'hm', 'lgbt', 'mlp', 'news', 'out', 'po', 'pw', 'qst', 'sp', 'trv', 'tv', 'vp', 'wsg', 'wsr',
  'x', 'y', '3', 'aco', 'adv', 'an', 'bant', 'biz', 'cgl', 'ck', 'co', 'diy', 'fa', 'fit', 'gd',
  'hc', 'his', 'int', 'jp', 'lit', 'mu', 'n', 'pol', 'sci', 'soc', 'tg', 'toy', 'vt', 'xs'
]);

// Define display names for channels (Key = short code, Value = Display Name)
define('CHANNEL_NAMES', [
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
  'tg' => 'Traditional Games', 'toy' => 'Toys', 'vt' => 'Virtual YouTubers', 'xs' => 'Extreme Sports'
  // Add more mappings here if you add channels to ALLOWED_CHANNELS
]);

// Define channels that should display an NSFW warning (use short codes)
define('NSFW_CHANNELS', ['b', 'd', 'gif', 'h', 'hr', 'r9k', 's', 'soc', 'x', 'y', 'aco', 'bant', 'hc', 'hm', 'pol', 'r', 's4s', 'lgbt']);

define('THREADS_PER_PAGE', 10);
define('REPLIES_PREVIEW_COUNT', 6);
define('COMMENT_PREVIEW_LENGTH', 1000); // Max characters before truncation in board view

// --- Initialization & DB Setup ---
ini_set('display_errors', 1); // Show errors during development - DISABLE IN PRODUCTION
error_reporting(E_ALL);

if (!is_dir(UPLOADS_DIR)) {
  if (!mkdir(UPLOADS_DIR, 0775, true)) {
    error_log("Error: Could not create uploads directory at " . UPLOADS_DIR);
    die("Error: Could not create uploads directory.");
  }
}
if (!is_writable(UPLOADS_DIR)) {
  error_log("Error: Uploads directory is not writable: " . UPLOADS_DIR);
  die("Error: The uploads directory '" . UPLOADS_DIR . "' is not writable.");
}

try {
  $db = new PDO('sqlite:' . DB_FILE);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

  // Create tables if they don't exist
  $db->exec("CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL DEFAULT '" . ALLOWED_CHANNELS[0] . "',
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
    comment TEXT NOT NULL,
    image TEXT,
    image_orig_name TEXT,
    image_w INTEGER,
    image_h INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
  )");

  // Add channel column if it doesn't exist
  try {
    $columns = $db->query("PRAGMA table_info(threads)")->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array('channel', $columns)) {
      $db->exec("ALTER TABLE threads ADD COLUMN channel TEXT NOT NULL DEFAULT '" . ALLOWED_CHANNELS[0] . "'");
    }
  } catch (PDOException $e) {
    error_log("Database ALTER TABLE error: " . $e->getMessage());
    // Don't die, just log and potentially show a non-fatal warning
    echo "<p class='error'>Warning: Could not update database schema. Error: " . htmlspecialchars($e->getMessage()) . "</p>";
  }

} catch (PDOException $e) {
  error_log("Database Connection Error: " . $e->getMessage());
  die("Database Connection Error: " . $e->getMessage());
}

// --- Functions ---

/**
 * Handles file uploads.
 */
function handle_upload($file_input_name) {
  if (!isset($_FILES[$file_input_name]) || $_FILES[$file_input_name]['error'] === UPLOAD_ERR_NO_FILE) {
    return ['success' => false]; // No file uploaded
  }

  $file = $_FILES[$file_input_name];

  if ($file['error'] !== UPLOAD_ERR_OK) {
    // Handle specific upload errors more gracefully
    switch ($file['error']) {
      case UPLOAD_ERR_INI_SIZE:
      case UPLOAD_ERR_FORM_SIZE: return ['error' => 'File is too large (Server limit).'];
      case UPLOAD_ERR_PARTIAL: return ['error' => 'File was only partially uploaded.'];
      case UPLOAD_ERR_NO_TMP_DIR: return ['error' => 'Missing temporary folder.'];
      case UPLOAD_ERR_CANT_WRITE: return ['error' => 'Failed to write file to disk.'];
      case UPLOAD_ERR_EXTENSION: return ['error' => 'A PHP extension stopped the upload.'];
      default: return ['error' => 'Unknown upload error (Code: ' . $file['error'] . ').'];
    }
  }

  if ($file['size'] > MAX_FILE_SIZE) {
    return ['error' => 'File is too large (Max: '.(MAX_FILE_SIZE / 1024 / 1024).' MB).'];
  }

  $file_info = pathinfo($file['name']);
  $extension = strtolower($file_info['extension'] ?? '');

  if (!in_array($extension, ALLOWED_EXTENSIONS)) {
    return ['error' => 'Invalid file type. Allowed: ' . implode(', ', ALLOWED_EXTENSIONS)];
  }

  // Get image dimensions if applicable
  $img_w = null;
  $img_h = null;
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
    $image_size = @getimagesize($file['tmp_name']);
    if ($image_size !== false) {
      $img_w = $image_size[0] ?? null;
      $img_h = $image_size[1] ?? null;
    }
  }

  $new_filename = uniqid() . time() . '.' . $extension;
  $destination = UPLOADS_DIR . '/' . $new_filename;

  if (move_uploaded_file($file['tmp_name'], $destination)) {
    if (!file_exists($destination)) { // Double check
      error_log("Failed confirm uploaded file existence: " . $destination);
      return ['error' => 'Failed to confirm file after move.'];
    }
    return [
      'success' => true,
      'filename' => $new_filename,
      'orig_name' => basename($file['name']),
      'width' => $img_w,
      'height' => $img_h
    ];
  } else {
    error_log("Failed to move uploaded file to " . $destination . ". Source: " . $file['tmp_name'] . ". Writable: " . (is_writable(UPLOADS_DIR)?'Yes':'No'));
    return ['error' => 'Failed to move uploaded file. Check permissions or disk space.'];
  }
}

/**
 * Determines the media type for rendering based on URL or filename.
 */
function get_render_media_type($url_or_filename) {
  // YouTube check (more robust)
  $youtube_regex = '/^https?:\/\/(?:www\.)?(?:m\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})(?:[?&].*)?$/i';
  if (preg_match($youtube_regex, $url_or_filename)) {
    return 'youtube';
  }
  // Extension check (from path info)
  $extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
  if (in_array($extension, VIDEO_EXTENSIONS)) return 'video';
  if (in_array($extension, AUDIO_EXTENSIONS)) return 'audio';

  // Check if it's just a local filename (no scheme) and test its extension
  if (!preg_match('/^https?:\/\//', $url_or_filename)) {
      $local_extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
      if (in_array($local_extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
      if (in_array($local_extension, VIDEO_EXTENSIONS)) return 'video';
      if (in_array($local_extension, AUDIO_EXTENSIONS)) return 'audio';
  }

  return 'unknown'; // Default if it's not a known media extension or YouTube URL
}


/**
 * Formats comment text: Sanitizes, NL2BR, Greentext, Reply Links, and basic Linkification.
 * IMPORTANT: htmlspecialchars IS necessary here for security.
 * This function now ONLY performs formatting *after* media links are extracted.
 */
function format_comment($comment) {
  $comment = (string) ($comment ?? '');

  // 1. Sanitize HTML to prevent XSS. THIS IS CRITICAL.
  $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');

  // 2. Basic Linkification (handles non-media links left in the text)
  // Simple regex, might catch unintended strings but generally safe after htmlspecialchars
  // It looks for http/https/ftp and turns it into a link. Avoids re-linking existing <a> tags.
  $comment = preg_replace_callback(
      '/(?<![\'"])(?<![=\/])(https?|ftp):\/\/([^\s<>"\'`]+)/i',
      function ($matches) {
          $url = $matches[0];
          $display_url = (mb_strlen($matches[2]) > 50) ? mb_substr($matches[2], 0, 47) . '...' : $matches[2]; // Shorten displayed text
          return '<a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer">' . htmlspecialchars(urldecode($matches[1] . '://' . $display_url), ENT_QUOTES, 'UTF-8') . '</a>';
      },
      $comment
  );

  // 3. Convert newlines to <br> (AFTER linkification)
  $comment = nl2br($comment, false); // Use false to avoid XHTML <br />

  // 4. Greentext (handles start of line or after <br>)
  $comment = preg_replace('/(^<br>|^\s*)(>[^>].*?)$/m', '$1<span class="greentext">$2</span>', $comment);
  $comment = preg_replace('/(^\s*)(>[^>].*?)$/m', '$1<span class="greentext">$2</span>', $comment); // Handles start of entire comment

  // 5. Reply Links (works on >> after sanitization which turns > into &gt;)
  // Need to adjust regex to look for &gt;&gt;
  $comment = preg_replace('/&gt;&gt;(\d+)/', '<a href="#post-$1" class="reply-mention">&gt;&gt;$1</a>', $comment);


  return $comment;
}

/**
 * Finds URLs in RAW text, separates media links, generates media buttons for them,
 * returns the text with media URLs removed and the generated button/container HTML.
 * *** MODIFIED: Ensures media buttons appear in the order links are found in the comment by appending HTML. ***
 */
function process_comment_media_links($text, $post_element_id) {
  $media_html = '';
  $cleaned_text = $text;
  $link_counter = 0;
  // Regex to find URLs (avoids matching inside existing tags like src/href, although less critical here as we process raw text)
  $url_regex = '/(?<!src=["\'])(?<!href=["\'])(https?|ftp):\/\/[^\s<>"]+/i';

  // Find all URLs with offsets
  if (preg_match_all($url_regex, $text, $matches, PREG_OFFSET_CAPTURE)) {
    // Process matches in reverse order of offset to avoid messing up indices during removal
    $matches_reversed = array_reverse($matches[0]);
    $media_items_to_append = []; // Store items to append in correct order

    foreach ($matches_reversed as $match) {
      $url = $match[0];
      $offset = $match[1];
      $render_type = get_render_media_type($url); // Check if it's a media type we handle

      if ($render_type !== 'unknown') {
        // This is a media URL - Store its info to process later
        $media_items_to_append[] = [
            'url' => $url,
            'offset' => $offset,
            'length' => strlen($url),
            'render_type' => $render_type
        ];
        // Remove the raw URL from the original text variable ($cleaned_text) immediately
        // This is safe because we process in reverse offset order
        $cleaned_text = substr_replace($cleaned_text, '', $offset, strlen($url));
      }
      // Else: It's a non-media URL, leave it in $cleaned_text for format_comment to handle linkification
    }

    // Now iterate through the found media items *in forward order* (reverse the stored array)
    // to generate HTML and append it, maintaining the original link order.
    foreach (array_reverse($media_items_to_append) as $item) {
        $link_counter++;
        // Ensure media_id is unique per link across the page by including the post/reply ID
        $media_id = $post_element_id . '-link-' . $link_counter; // Unique ID per link within the post
        $safe_url = htmlspecialchars($item['url'], ENT_QUOTES, 'UTF-8'); // Sanitize URL for use in attributes/display
        $render_type = $item['render_type'];

        // Determine button text based on type
        $button_text = 'View Media';
        if ($render_type === 'image') $button_text = 'View Image';
        elseif ($render_type === 'video') $button_text = 'View Video';
        elseif ($render_type === 'audio') $button_text = 'View Audio';
        elseif ($render_type === 'youtube') $button_text = 'View YouTube';

        // Generate the HTML for the button and its container, *** APPEND *** it to $media_html
        // Use data attributes extensively for JS interaction
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
          <div id='media-container-{$media_id}' class='media-container' style='display:none;'></div>"; // Append HTML
    }
  }

  // Return the text (now without media URLs) and the generated HTML for media buttons/containers
  return ['cleaned_text' => trim($cleaned_text), 'media_html' => $media_html];
}


// --- Determine Current View (Board Index or Specific Channel/Thread) ---
$show_board_index = true; // Assume board index view by default
$current_channel_code = null;
$current_channel_display_name = 'Board Index'; // Default title part

$requested_channel = $_GET['channel'] ?? null;
if ($requested_channel !== null && in_array($requested_channel, ALLOWED_CHANNELS)) {
  $current_channel_code = $requested_channel;
  $current_channel_display_name = CHANNEL_NAMES[$current_channel_code] ?? $current_channel_code;
  $show_board_index = false; // We have a valid channel, show channel view
}

// --- Determine if viewing a specific thread (only relevant if not showing board index) ---
$viewing_thread_id = null;
if (!$show_board_index) {
  $viewing_thread_id = filter_input(INPUT_GET, 'thread', FILTER_VALIDATE_INT);
}


// --- Handle Post Request (Only applicable to Channel/Thread views) ---
$post_error = null;
$post_success = null; // Will likely not be displayed if redirect occurs

// Check if it's a POST request AND we are NOT showing the board index
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$show_board_index && isset($_POST['comment'])) {
  $comment_raw = trim($_POST['comment'] ?? ''); // Get raw comment first
  $subject = trim($_POST['subject'] ?? ''); // Only for new threads
  $thread_id = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT); // For replies
  $posted_channel_code = trim($_POST['channel'] ?? ''); // The short code submitted from the form

  // --- Basic Validation (ensure channel code from form matches current context if possible) ---
  if (!$thread_id && $posted_channel_code !== $current_channel_code) {
    $post_error = "Channel mismatch detected. Please post from the correct board page.";
  } else {
    // --- Process comment to see if it contains non-media text or only media links ---
    // We need to check content *after* potentially removing media links
    // Use a dummy ID for this validation check as we don't have the real post ID yet
    $temp_media_check = process_comment_media_links($comment_raw, 'temp-validation');
    $has_text_content = !empty(trim($temp_media_check['cleaned_text'])); // Check if text remains after removing media links
    $has_media_links = !empty($temp_media_check['media_html']); // Check if media links were found
    $has_file = isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE;

    if (!$has_text_content && !$has_media_links && !$has_file) {
      $post_error = "A comment, a file, or media links are required.";
    } elseif (mb_strlen($comment_raw) > 4000) { // Check length on the original comment
      $post_error = "Post content is too long (max 4000 characters).";
    } elseif (!$thread_id && empty($posted_channel_code)) { // Should not happen if previous check passes
      $post_error = "Channel not specified for new thread.";
    } elseif (!$thread_id && !in_array($posted_channel_code, ALLOWED_CHANNELS)) { // Should not happen if previous check passes
      $post_error = "Invalid channel specified.";
    } else {
      // Handle file upload
      $upload_result = handle_upload('image');

      if (isset($upload_result['error'])) {
        $post_error = $upload_result['error'];
      } else {
        try {
          $db->beginTransaction();

          $image_filename = $upload_result['filename'] ?? null;
          $image_orig_name = $upload_result['orig_name'] ?? null;
          $image_w = $upload_result['width'] ?? null;
          $image_h = $upload_result['height'] ?? null;

          // Final check: Ensure there's *something* to post if no file was uploaded
          if (!$has_file && !$has_text_content && !$has_media_links) {
               $db->rollBack(); // Rollback if somehow we got here without content
               $post_error = "A comment, a file, or media links are required.";
          } else {
            if ($thread_id) { // Posting a Reply
              // Verify thread exists and get its channel (important for redirect)
              $stmt = $db->prepare("SELECT id, channel FROM threads WHERE id = ?");
              $stmt->execute([$thread_id]);
              $thread_data = $stmt->fetch();

              if ($thread_data) {
                // Ensure reply is posted to the correct channel context (based on thread's channel)
                if ($thread_data['channel'] !== $current_channel_code) {
                  $db->rollBack();
                  $post_error = "Attempting to reply to a thread from the wrong channel page.";
                } else {
                  // Store the RAW comment in the DB
                  $stmt = $db->prepare("INSERT INTO replies (thread_id, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?)");
                  $stmt->execute([$thread_id, $comment_raw, $image_filename, $image_orig_name, $image_w, $image_h]);
                  $new_post_id = $db->lastInsertId();

                  $stmt = $db->prepare("UPDATE threads SET last_reply_at = CURRENT_TIMESTAMP WHERE id = ?");
                  $stmt->execute([$thread_id]);

                  $db->commit();
                  // Redirect back to the thread view including the new reply anchor
                  $redirect_params = ['channel' => $thread_data['channel'], 'thread' => $thread_id];
                  $redirect_url = './?' . http_build_query($redirect_params) . '&ts=' . time() . '#post-' . $new_post_id;
                  header("Location: " . $redirect_url);
                  exit;
                }
              } else {
                $post_error = "Thread not found.";
                $db->rollBack();
              }

            } else { // Posting a New Thread
              // Use the validated $current_channel_code
              // Store the RAW comment in the DB
              $stmt = $db->prepare("INSERT INTO threads (channel, subject, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?)");
              $stmt->execute([$current_channel_code, $subject, $comment_raw, $image_filename, $image_orig_name, $image_w, $image_h]);
              $new_post_id = $db->lastInsertId();

              $db->commit();
              // Redirect back to the board view of the current channel
              $redirect_params = ['channel' => $current_channel_code];
              $redirect_url = './?' . http_build_query($redirect_params) . '&ts=' . time();
              header("Location: " . $redirect_url);
              exit;
            }
          } // End content check

        } catch (PDOException $e) {
          if ($db->inTransaction()) { // Check if transaction is active before rollback
              $db->rollBack();
          }
          error_log("Database Post Error: " . $e->getMessage());
          $post_error = "Database Error: Could not save post. " . htmlspecialchars($e->getMessage());
        }
      }
    }
  } // End channel mismatch check
  // Continue script execution only if there was a post error (no redirect occurred)
} // End POST request handling


// --- Fetch Data for Display ---
$threads = [];
$replies_to_display = []; // Preview for board, all for thread
$reply_counts = [];
$total_threads = 0;
$total_pages = 1;
$thread_op = null;
$current_page = 1;
$board_index_data = []; // For the new board index view


if ($show_board_index) {
  // --- Board Index View ---
  try {
    // Prepare statements outside the loop for efficiency
    $thread_count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
    $reply_count_stmt = $db->prepare("SELECT COUNT(r.id) FROM replies r JOIN threads t ON r.thread_id = t.id WHERE t.channel = ?");

    foreach (ALLOWED_CHANNELS as $channel_code) {
      $display_name = CHANNEL_NAMES[$channel_code] ?? $channel_code;

      // Get thread count
      $thread_count_stmt->execute([$channel_code]);
      $thread_count = $thread_count_stmt->fetchColumn();

      // Get reply count
      $reply_count_stmt->execute([$channel_code]);
      $reply_count = $reply_count_stmt->fetchColumn();

      $total_posts = $thread_count + $reply_count;

      $board_index_data[] = [
        'code' => $channel_code,
        'name' => $display_name,
        'total_posts' => $total_posts
      ];
    }
    // Keep the order defined in ALLOWED_CHANNELS

  } catch (PDOException $e) {
    error_log("Database Fetch Error (Board Index): " . $e->getMessage());
    die("Database Fetch Error: " . $e->getMessage());
  }

} else {
  // --- Channel/Thread View ---
  try {
    if ($viewing_thread_id) {
      // --- Thread View ---
      $stmt = $db->prepare("SELECT * FROM threads WHERE id = ? AND channel = ?"); // Also check channel match
      $stmt->execute([$viewing_thread_id, $current_channel_code]);
      $thread_op = $stmt->fetch();

      if ($thread_op) {
        // Channel context is already correct from the initial check

        // Fetch all replies
        $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id = ? ORDER BY created_at ASC");
        $replies_stmt->execute([$viewing_thread_id]);
        $replies_to_display[$viewing_thread_id] = $replies_stmt->fetchAll();
        $reply_counts[$viewing_thread_id] = count($replies_to_display[$viewing_thread_id]);

        $threads = [$thread_op]; // Keep structure consistent

      } else {
        // Thread not found OR belongs to a different channel
        $post_error = "Thread with ID " . htmlspecialchars($viewing_thread_id) . " not found in channel /" . htmlspecialchars($current_channel_code) . "/.";
        // Reset context to show the board view of the *requested* channel
        $viewing_thread_id = null;
        // Fall through to board view logic implicitly by $viewing_thread_id being null now
      }
    }

    // --- Board View (or fallback from invalid thread ID) ---
    if (!$viewing_thread_id) {
      $current_page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT);
      if ($current_page <= 0) $current_page = 1;

      // Get total thread count for the current channel code
      $count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
      $count_stmt->execute([$current_channel_code]);
      $total_threads = $count_stmt->fetchColumn();
      $total_pages = ceil($total_threads / THREADS_PER_PAGE);
      if ($total_pages == 0) $total_pages = 1; // Always at least 1 page

      // Adjust current page if out of bounds
      if ($current_page > $total_pages) $current_page = $total_pages;
      $offset = ($current_page - 1) * THREADS_PER_PAGE;

      // Fetch threads for the current page
      $threads_stmt = $db->prepare("SELECT * FROM threads WHERE channel = ? ORDER BY last_reply_at DESC LIMIT ? OFFSET ?");
      $threads_stmt->bindValue(1, $current_channel_code, PDO::PARAM_STR);
      $threads_stmt->bindValue(2, THREADS_PER_PAGE, PDO::PARAM_INT);
      $threads_stmt->bindValue(3, $offset, PDO::PARAM_INT);
      $threads_stmt->execute();
      $threads = $threads_stmt->fetchAll();

      // Fetch reply previews and counts for threads on this page
      $threads_on_page_ids = array_column($threads, 'id');

      if (!empty($threads_on_page_ids)) {
        $placeholders = implode(',', array_fill(0, count($threads_on_page_ids), '?'));

        // Fetch total counts
        $count_stmt = $db->prepare("SELECT thread_id, COUNT(*) as count FROM replies WHERE thread_id IN ($placeholders) GROUP BY thread_id");
        $count_stmt->execute($threads_on_page_ids);
        while($row = $count_stmt->fetch()) {
          $reply_counts[$row['thread_id']] = $row['count'];
        }

        // Fetch all replies for these threads to get the last N for preview
        $all_replies_for_page = [];
        $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id IN ($placeholders) ORDER BY created_at ASC");
        $replies_stmt->execute($threads_on_page_ids);
        while ($reply = $replies_stmt->fetch()) {
          $all_replies_for_page[$reply['thread_id']][] = $reply;
        }

        // Get the last N replies for preview
        foreach ($all_replies_for_page as $tid => $thread_replies) {
          $start_index = max(0, count($thread_replies) - REPLIES_PREVIEW_COUNT);
          $replies_to_display[$tid] = array_slice($thread_replies, $start_index);
        }
      }
    }

  } catch (PDOException $e) {
    error_log("Database Fetch Error (Channel/Thread): " . $e->getMessage());
    die("Database Fetch Error: " . $e->getMessage()); // Keep dying on fetch errors
  }
} // End Channel/Thread View Data Fetching
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/HDBoard.png">
    <title><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code) . '/ - ' . htmlspecialchars($current_channel_display_name) . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></title>
    <style>
      /* --- Dark Mode Base Styles --- */
      :root {
        --bg-color: #1a1a1a; /* Very dark grey */
        --text-color: #e0e0e0; /* Light grey text */
        --border-color: #444; /* Mid-dark grey border */
        --post-bg: #282828; /* Slightly lighter post background */
        --header-bg: #333; /* Darker header background */
        --link-color: #7aa2f7; /* Light blue links */
        --link-hover: #c0caf5; /* Lighter blue on hover */
        --accent-red: #f7768e; /* Muted red */
        --accent-green: #9ece6a; /* Muted green */
        --accent-blue: #4f6dac; /* Muted blue */
        --greentext-color: #9ece6a; /* Green text */
        --reply-mention-color: #f7768e; /* Red reply links */
        --form-bg: #303030;
        --input-bg: #404040;
        --input-text: #e0e0e0;
        --input-border: #555;
        --button-bg: #555;
        --button-hover-bg: #666;
        --button-text: #e0e0e0;
        --warning-bg: #5c2424; /* Dark red background */
        --warning-border: #a04040; /* Brighter red border */
        --warning-text: #f7768e; /* Light red text */
        --success-bg: #2a502a;
        --success-border: #4a804a;
        --success-text: #9ece6a;
        --error-bg: var(--warning-bg);
        --error-border: var(--warning-border);
        --error-text: var(--warning-text);
        --code-bg: #333;
        --code-text: #ccc;
        --board-index-item-bg: var(--post-bg);
        --board-index-item-border: var(--border-color);
        --board-index-item-hover-bg: #383838;
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

      /* Header & Navigation */
      header {
        background-color: var(--header-bg);
        border: 1px solid var(--border-color);
        border-bottom-width: 2px; /* Slightly thicker bottom border */
        margin-bottom: 15px;
        padding: 10px;
        text-align: center;
      }
      header h1 {
        color: var(--accent-red);
        margin: 5px 0;
        font-size: 1.8em;
      }

      /* Beautified Channel Navigation */
      .channel-nav {
        margin-top: 10px;
        padding: 10px 0;
        border-top: 1px dashed var(--border-color);
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 5px 10px; /* Row gap, Column gap */
      }
       .channel-nav a, .board-index-home-link {
        display: inline-block;
        padding: 4px 8px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background-color: var(--post-bg); /* Use post background for consistency */
        color: var(--link-color);
        font-weight: normal;
        transition: background-color 0.2s ease, border-color 0.2s ease;
        margin-bottom: 5px; /* Ensure spacing on wrap */
      }
      .channel-nav a:hover, .board-index-home-link:hover {
        background-color: var(--button-hover-bg);
        border-color: var(--link-hover);
        color: var(--link-hover);
        text-decoration: none;
      }
      .channel-nav a.active {
        background-color: var(--accent-blue);
        color: var(--button-text);
        border-color: var(--link-color);
        font-weight: bold;
      }
      /* Specific style for Home link when active (on board index page) */
       .board-index-home-link.active {
        background-color: var(--accent-red); /* Use a different color for Home */
        color: var(--button-text);
        border-color: var(--accent-red);
        font-weight: bold;
       }

      /* NSFW Warning Banner */
      .nsfw-warning {
        background-color: var(--warning-bg);
        border: 1px solid var(--warning-border);
        color: var(--warning-text);
        padding: 10px 30px 10px 10px; /* More padding on right for button */
        margin-bottom: 15px;
        text-align: center;
        font-weight: bold;
        position: relative; /* Needed for positioning the close button */
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

      /* Post Form */
      .post-form, .reply-form-container {
        background-color: var(--form-bg);
        border: 1px solid var(--border-color);
        padding: 15px;
        margin-bottom: 20px;
      }
      .post-form table, .reply-form-container table {
        border-collapse: collapse;
        width: 100%;
      }
      .post-form th, .post-form td,
      .reply-form-container th, .reply-form-container td {
        padding: 6px;
        vertical-align: top;
        text-align: left;
      }
      .post-form th, .reply-form-container th {
        width: 100px;
        text-align: right;
        font-weight: bold;
        color: var(--text-color); /* Labels readable */
        padding-right: 10px;
      }
      .reply-form-container th {
        width: 80px; /* Smaller label width for reply form */
      }
      .post-form td, .reply-form-container td {
        width: auto;
      }

      .post-form input[type="text"],
      .post-form textarea,
      .post-form select,
      .reply-form-container input[type="text"],
      .reply-form-container textarea {
        width: calc(100% - 16px); /* Account for padding */
        padding: 7px;
        border: 1px solid var(--input-border);
        box-sizing: border-box;
        font-size: 1em;
        background-color: var(--input-bg);
        color: var(--input-text);
      }
      .post-form textarea, .reply-form-container textarea {
        resize: vertical;
      }
      .post-form input[type="file"], .reply-form-container input[type="file"] {
        padding: 5px 0;
        color: var(--text-color);
      }
      /* Style file input button slightly */
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


      .post-form input[type="submit"], .reply-form-container input[type="submit"] {
        padding: 6px 15px;
        font-weight: bold;
        cursor: pointer;
        background-color: var(--button-bg);
        color: var(--button-text);
        border: 1px solid var(--input-border);
        border-radius: 3px;
      }
      .post-form input[type="submit"]:hover, .reply-form-container input[type="submit"]:hover {
        background-color: var(--button-hover-bg);
      }
      .post-form small, .reply-form-container small {
        color: #aaa; /* Lighter grey for help text */
        font-size: 0.9em;
      }

      hr {
        border: 0;
        border-top: 1px solid var(--border-color);
        margin: 25px 0;
      }

      /* --- Board Index View --- */
      .board-index-list {
        list-style: none;
        padding: 0;
        margin: 20px 0;
        display: grid; /* Use grid for better layout control */
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* Responsive columns */
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
        display: block; /* Ensure name takes full width */
        margin-top: 3px;
        font-size: 0.95em;
        color: var(--text-color); /* Use main text color */
      }
      .board-index-list .board-post-count {
        display: block;
        font-size: 0.85em;
        color: #aaa; /* Lighter grey for count */
        margin-top: 5px;
        text-align: right;
      }

      /* Posts (Threads/Replies) - Existing Styles */
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
        max-width: calc(100% - 20px); /* Adjust max-width for potential scrollbars within */
        min-width: 200px;
        box-sizing: border-box;
       }

      .post-info {
        color: var(--accent-green); /* Greenish info */
        font-weight: bold;
        margin-bottom: 5px;
        font-size: 0.95em;
      }
      .post-info .subject {
        color: var(--accent-blue); /* Bluish subject */
        margin-right: 5px;
      }
      .post-info .name {
          /* Optional: Style Anonymous name if needed */
          color: var(--accent-green);
      }
      .post-info .time, .post-info .post-id {
        font-size: 0.9em;
        color: #bbb; /* Lighter grey for time/id */
        font-weight: normal;
        margin-left: 8px;
      }
      .post-info .reply-link { /* Includes View/Reply/[>] */
        font-size: 0.9em;
        color: #bbb;
        text-decoration: none;
        font-weight: normal;
        margin-left: 8px;
      }
      .post-info .reply-link a { /* Style the actual <a> inside */
         color: var(--link-color);
      }
      .post-info .reply-link a:hover {
        color: var(--link-hover);
      }
      .post-info .reply-count {
        font-size: 0.9em;
        color: #bbb;
        font-weight: normal;
        margin-left: 5px;
      }

      /* File/Media Info & Toggle (Applied to both uploaded and linked media) */
      .file-info {
        font-size: 0.9em;
        color: #ccc; /* Light grey for file details */
        margin-bottom: 8px; /* Space below each file/link block */
        display: flex;
        align-items: flex-start; /* Align items to the top */
        flex-wrap: wrap;
        gap: 5px 10px; /* Vertical gap, Horizontal gap */
        border-bottom: 1px dashed var(--border-color); /* Separator line */
        padding-bottom: 5px;
        margin-top: 5px; /* Add some space above */
      }
      .file-info:last-of-type {
        border-bottom: none; /* No border for the last item */
        margin-bottom: 10px; /* More space after the last media item before comment */
      }
      .file-info .media-toggle {
        flex-shrink: 0; /* Prevent button from shrinking */
      }
      .file-info .media-toggle button.show-media-btn {
        padding: 4px 8px;
        cursor: pointer;
        font-size: 0.9em;
        background-color: var(--button-bg);
        border: 1px solid var(--input-border);
        border-radius: 3px;
        color: var(--button-text);
        line-height: 1.2; /* Adjust line height */
        text-transform: none;
        white-space: normal; /* Allow button text to wrap if needed */
        text-align: center;
      }
      .file-info .media-toggle button.show-media-btn:hover {
        background-color: var(--button-hover-bg);
      }
      .file-details {
        flex-grow: 1; /* Allow details to take remaining space */
        line-height: 1.4; /* Match button line height */
        word-break: break-all; /* Allow long filenames/links to break */
      }
      .file-details a {
        color: var(--link-color);
        text-decoration: underline;
      }
      .file-details a:hover {
        color: var(--link-hover);
      }

      /* Media Container (Holds the actual img/video/audio/iframe) */
      .media-container {
        margin-top: 8px;
        margin-bottom: 10px;
        border: 1px dashed var(--border-color);
        padding: 5px;
        display: none; /* Hidden by default, toggled by JS */
        max-width: 100%; /* Prevent overflow */
        box-sizing: border-box;
        overflow: hidden; /* Hide potential overflow */
        background-color: var(--bg-color); /* Ensure background for padding */
      }
      .media-container img,
      .media-container video,
      .media-container audio,
      .media-container iframe {
        display: block;
        max-width: 100%; /* Ensure media fits container */
        height: auto; /* Maintain aspect ratio */
        margin: 0 auto; /* Center block elements */
        background-color: #000; /* Black bg for media loading */
      }
      .media-container audio {
        width: 100%; /* Make audio controls take full width */
        /* Consider filter for dark theme controls if native look is bad */
        /* filter: invert(1) hue-rotate(180deg); */
      }

      /* Aspect Ratio Containers for Video/YouTube */
      .youtube-embed-container, .video-embed-container {
        margin: 5px 0; /* Reduced margin */
        position: relative;
        padding-bottom: 56.25%; /* 16:9 aspect ratio */
        height: 0;
        overflow: hidden;
        max-width: 100%;
        background: #000; /* Black background */
      }
      .youtube-embed-container iframe,
      .video-embed-container video {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        border: none; /* Remove iframe border */
      }

      /* Comment Styling */
      .comment {
        margin-top: 10px; /* Space above comment text */
        line-height: 1.5;
        overflow-wrap: break-word;
        word-break: break-word;
        color: var(--text-color); /* Ensure comment text uses main text color */
      }
      .comment-truncated { display: block; } /* Visible by default */
      .comment-full { display: none; } /* Hidden by default */
      .show-full-text-btn {
        display: inline-block; /* Allow margin */
        padding: 2px 5px;
        font-size: 0.8em;
        cursor: pointer;
        margin-left: 5px;
        margin-top: 5px; /* Add some space above */
        background-color: var(--button-bg);
        border: 1px solid var(--input-border);
        border-radius: 3px;
        color: var(--button-text);
      }
      .show-full-text-btn:hover { background-color: var(--button-hover-bg); }

      .greentext { color: var(--greentext-color); }
      .reply-mention {
        color: var(--reply-mention-color);
        text-decoration: none; /* Remove underline from >> links */
        font-weight: bold;
      }
      .reply-mention:hover {
        color: var(--link-hover);
        text-decoration: underline; /* Underline on hover */
       }

      /* Omitted Posts */
      .omitted-posts {
        font-size: 0.9em;
        color: #aaa;
        margin-left: 20px;
        margin-top: 5px;
        margin-bottom: 10px;
      }
      .omitted-posts a { color: var(--link-color); text-decoration: none; }
      .omitted-posts a:hover { text-decoration: underline; }

      /* Success/Error Messages */
      .error, .success {
        font-weight: bold;
        border: 1px solid;
        padding: 10px;
        margin-bottom: 15px;
        border-radius: 4px;
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

      /* Pagination */
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
        background-color: var(--header-bg); /* Darker disabled background */
        border-color: var(--border-color);
      }

      /* Thread View Specific */
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

      /* Anchor scroll padding */
      :target {
        scroll-margin-top: 70px; /* Adjust to account for fixed header or other elements */
      }

       /* Highlight on target */
       .post.highlighted, .reply.highlighted {
           background-color: #404050 !important; /* Use !important carefully */
           border-color: var(--link-color) !important;
           transition: background-color 0.3s ease, border-color 0.3s ease;
       }


      /* Reply form specific in thread view */
      #post-form h4, .reply-form-container h4 {
         margin: 0 0 10px 0;
         color: var(--accent-blue);
      }


      /* --- Responsive Styles --- */
      @media (max-width: 767px) {
        body { font-size: 11pt; }
        .container { padding: 0 10px; }
        header h1 { font-size: 1.5em; }
        .channel-nav { font-size: 0.9em; gap: 4px 8px; } /* Adjust gap */
        .board-index-list { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); } /* Smaller min width on mobile */


        .post-form th, .reply-form-container th {
          width: auto;
          text-align: left;
          display: block;
          padding-bottom: 2px; /* Space between stacked label and input */
          padding-right: 6px;
        }
        .post-form td, .reply-form-container td {
          display: block;
          padding-top: 0;
        }
        .post-form input[type="text"],
        .post-form textarea,
        .post-form select,
        .reply-form-container input[type="text"],
        .reply-form-container textarea {
          width: calc(100% - 12px); /* Adjust width */
          padding: 6px;
        }
        .post-form input[type="submit"], .reply-form-container input[type="submit"] {
          display: block;
          width: auto; /* Don't make submit full width */
          margin-top: 10px;
        }

        /* Stack file info elements on mobile */
        .file-info { flex-direction: column; align-items: stretch; gap: 5px 0; }
        .file-info .media-toggle { margin-bottom: 5px; }
        .file-info .file-details { margin-top: 0; font-size: 1em;}

        .reply-container { margin-left: 0; }
        .reply, .omitted-posts, .reply-form-container {
          margin-left: 5px;
          margin-right: 5px;
          max-width: calc(100% - 10px);
          min-width: auto;
        }

        .post-info { font-size: 0.9em; }
        .post-info .time, .post-info .post-id, .post-info .reply-link { font-size: 1em; margin-left: 4px; display: inline-block; margin-bottom: 3px; /* Stack info slightly better */ }
        .post-info .reply-count { margin-left: 4px; }


        .pagination { font-size: 1em; }
        .pagination a, .pagination span { padding: 3px 6px; }
        .thread-view-header { font-size: 1em; }
        :target { scroll-margin-top: 60px; } /* Adjust scroll margin for mobile */
      }

      @media (min-width: 768px) {
        .post-form th { width: 100px; text-align: right; display: table-cell; }
        .post-form td { display: table-cell; }
        .reply-form-container th { width: 80px; }

        /* Restore flex row for file info on larger screens */
        .file-info { flex-direction: row; align-items: flex-start; gap: 5px 10px; }
        .file-info .media-toggle { margin-bottom: 0; }
        .file-info .file-details { margin-top: 0; } /* Reset top margin */

        .reply-container { margin-left: 20px; }
        .reply, .omitted-posts, .reply-form-container {
           margin-left: 20px;
           margin-right: 0;
           max-width: calc(100% - 20px);
        }
      }

      .flex-container {
        display: flex;            /* Enable Flexbox */
        justify-content: center; /* Center items horizontally */
        /* align-items: center; */  /* Uncomment to center vertically too (if container has height) */
      }

      /* Optional: Ensure image doesn't overflow container */
      .flex-container img {
        max-width: 100%;
        height: 250px;
      }
    </style>
    <script>
      // Define media types handled by the dynamic loader
      const IMAGE_TYPES = ['image'];
      const VIDEO_TYPES = ['video'];
      const AUDIO_TYPES = ['audio'];
      const YOUTUBE_TYPE = 'youtube';

      // Simple toggle for reply form visibility
      function toggleReplyForm(threadId) {
        var form = document.getElementById('reply-form-' + threadId);
        if (form) {
          var isHidden = (form.style.display === 'none' || form.style.display === '');
          form.style.display = isHidden ? 'block' : 'none';
          if (isHidden) {
            form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            // Optionally focus the textarea
            const textarea = form.querySelector('textarea[name="comment"]');
            if (textarea) {
              textarea.focus();
            }
          }
        }
      }

      // Toggle media visibility and load content dynamically
      // *** MODIFIED: Find the media container structurally instead of solely by ID ***
      function toggleMedia(button) { // Only need the button element as argument
        // Find the parent .file-info div
        const fileInfoDiv = button.closest('.file-info');
        if (!fileInfoDiv) {
            console.error("Toggle Media Error: Could not find parent .file-info for button.", button);
            return;
        }

        // The media container is the immediate next sibling of the .file-info div
        const mediaContainer = fileInfoDiv.nextElementSibling;

        // Verify that the found element is indeed a media container
        if (!mediaContainer || !mediaContainer.classList.contains('media-container')) {
            console.error("Toggle Media Error: Could not find the adjacent .media-container sibling for button.", button, "Next sibling found:", mediaContainer);
            return;
        }

        // Get necessary data attributes from the button
        const mediaId = button.dataset.mediaId; // Still get ID for data-loaded-url check
        const mediaUrl = button.dataset.mediaUrl;
        const mediaType = button.dataset.mediaType;

        if (!mediaId || !mediaUrl || !mediaType) {
             console.error("Toggle Media Error: Missing data attributes on button.", button);
             return;
        }
         // Optional: Validate found container ID matches button's data-media-id (extra check)
         if (mediaContainer.id !== ('media-container-' + mediaId)) {
             console.warn("Toggle Media Warning: Found container by structure, but ID mismatch.", "Button ID:", mediaId, "Container ID:", mediaContainer.id);
             // We proceed with the found container, trusting the structure over ID lookup here
         }


        const isHidden = (mediaContainer.style.display === 'none' || mediaContainer.style.display === '');

        // Determine button text based on type and state
        let viewButtonText = 'View Media';
        if (IMAGE_TYPES.includes(mediaType)) viewButtonText = 'View Image';
        else if (VIDEO_TYPES.includes(mediaType)) viewButtonText = 'View Video';
        else if (AUDIO_TYPES.includes(mediaType)) viewButtonText = 'View Audio';
        else if (mediaType === YOUTUBE_TYPE) viewButtonText = 'View YouTube';

        let hideButtonText = 'Hide Media';
        if (IMAGE_TYPES.includes(mediaType)) hideButtonText = 'Hide Image';
        else if (VIDEO_TYPES.includes(mediaType)) hideButtonText = 'Hide Video';
        else if (AUDIO_TYPES.includes(mediaType)) hideButtonText = 'Hide Audio';
        else if (mediaType === YOUTUBE_TYPE) hideButtonText = 'Hide YouTube';

        if (isHidden) {
          // Show container and set button text
          mediaContainer.style.display = 'block';
          button.textContent = hideButtonText;

          // Load media if not already loaded or if URL changed (unlikely here)
          if (mediaContainer.innerHTML.trim() === '' || mediaContainer.dataset.loadedUrl !== mediaUrl) {
            mediaContainer.innerHTML = '<span>Loading...</span>'; // Add loading indicator
            mediaContainer.dataset.loadedUrl = mediaUrl; // Mark as loaded

            let mediaElementHTML = '';
            if (IMAGE_TYPES.includes(mediaType)) {
              // Wrap image in a link to the full image
              mediaElementHTML = `<a href="${mediaUrl}" target="_blank" rel="noopener noreferrer"><img src="${mediaUrl}" alt="Media Image" loading="lazy"></a>`;
            } else if (VIDEO_TYPES.includes(mediaType)) {
              // Use the aspect ratio container
              mediaElementHTML = `<div class="video-embed-container"><video src="${mediaUrl}" controls playsinline preload="metadata"></video></div>`;
            } else if (AUDIO_TYPES.includes(mediaType)) {
              mediaElementHTML = `<audio src="${mediaUrl}" controls preload="metadata"></audio>`;
            } else if (mediaType === YOUTUBE_TYPE) {
              // Extract YouTube video ID (more robust regex)
              const youtubeRegexMatch = mediaUrl.match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|m\.youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/);
              const videoId = (youtubeRegexMatch && youtubeRegexMatch[1]) ? youtubeRegexMatch[1] : null;
              if (videoId) {
                const embedUrl = `https://www.youtube.com/embed/${videoId}`;
                // Use the aspect ratio container
                mediaElementHTML = `<div class="youtube-embed-container"><iframe src="${embedUrl}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen loading="lazy"></iframe></div>`;
              } else {
                mediaElementHTML = '<span class="error">Failed to embed YouTube video (Invalid URL).</span>';
              }
            } else {
              mediaElementHTML = '<span class="error">Unsupported media type: ' + mediaType + '</span>';
            }
            // Replace loading indicator with actual media HTML
            mediaContainer.innerHTML = mediaElementHTML;
          }
        } else {
          // Hide container and reset button text
          mediaContainer.style.display = 'none';
          button.textContent = viewButtonText;

          // Stop media playback when hiding
          mediaContainer.querySelectorAll('video, audio, iframe').forEach(mediaElement => {
            if (mediaElement.tagName === 'VIDEO' || mediaElement.tagName === 'AUDIO') {
              if (typeof mediaElement.pause === 'function' && !mediaElement.paused) {
                mediaElement.pause();
              }
            }
            // Attempt to stop YouTube iframe using postMessage API
            else if (mediaElement.tagName === 'IFRAME' && mediaElement.src.includes('youtube.com/embed')) {
              try {
                 // Clearing the src attribute is a simple way to stop playback and unload
                 mediaElement.src = '';
                 // Alternatively, use postMessage if iframe hasn't been removed/re-added:
                 // if (mediaElement.contentWindow) {
                 //   mediaElement.contentWindow.postMessage('{"event":"command","func":"pauseVideo","args":""}', '*');
                 //   mediaElement.contentWindow.postMessage('{"event":"command","func":"stopVideo","args":""}', '*');
                 // }
              } catch (e) {
                console.warn("Could not stop YouTube iframe playback.", e);
              }
            }
          });
           // Clear innerHTML when hiding to ensure it's reloaded on next show,
           // which helps with stopping embeds and handling potential content changes.
           mediaContainer.innerHTML = '';
           delete mediaContainer.dataset.loadedUrl; // Remove loaded marker
        }
      }

      // Toggle full text visibility for truncated comments
      function toggleFullText(button, fullTextId) {
        const truncatedDiv = button.closest('.comment-truncated');
        const fullDiv = document.getElementById(fullTextId);
        if (truncatedDiv && fullDiv) {
          truncatedDiv.style.display = 'none'; // Hide truncated part + button
          fullDiv.style.display = 'block'; // Show full text
        }
      }

      // --- DOM Ready Event Listener ---
      document.addEventListener('DOMContentLoaded', function() {

        // --- Event Delegation for Dynamic Elements ---

        document.body.addEventListener('click', function(event) {
          // Media toggle buttons
          if (event.target.matches('.show-media-btn')) {
             // Pass the button element directly to toggleMedia
            toggleMedia(event.target);
          }
          // Text expansion buttons
          else if (event.target.matches('.show-full-text-btn')) {
            const fullTextId = event.target.dataset.targetId;
             if (fullTextId) {
              toggleFullText(event.target, fullTextId);
            }
          }
          // NSFW Warning Close Button
          else if (event.target.matches('#nsfw-warning-close')) {
             const nsfwWarning = document.getElementById('nsfw-warning');
             if (nsfwWarning) {
                 nsfwWarning.style.display = 'none';
             }
          }
          // Quick Reply Links (using event delegation)
          else if (event.target.matches('.reply-link[href^="#reply-form-"]')) {
              event.preventDefault(); // Prevent default jump
              const threadIdMatch = event.target.getAttribute('href').match(/#reply-form-(\d+)/);
              if (threadIdMatch && threadIdMatch[1]) {
                const threadId = threadIdMatch[1];
                toggleReplyForm(threadId);
              }
          }
        });


        // --- Reply Mention Hover/Click Highlighting ---
        let highlightTimeout = null;

        function highlightPost(targetPost, addClass) {
            if (!targetPost) return;
            if (addClass) {
                targetPost.classList.add('highlighted');
                // Remove highlight after a delay
                clearTimeout(highlightTimeout); // Clear previous timeout if any
                highlightTimeout = setTimeout(() => {
                    targetPost.classList.remove('highlighted');
                }, 1500); // Highlight duration in ms
            } else {
                targetPost.classList.remove('highlighted');
                 clearTimeout(highlightTimeout); // Clear timeout if mouse leaves before it fires
            }
        }

        // Highlight on hover
        document.body.addEventListener('mouseover', function(event) {
          // Use closest to handle clicks on children of the link if needed
          const replyMentionLink = event.target.closest('.reply-mention');
          if (replyMentionLink) {
            const targetId = replyMentionLink.getAttribute('href')?.substring(1); // Get target ID like "post-123"
            if (!targetId) return;
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply'); // Find parent post/reply div
            highlightPost(targetPost, true); // Add highlight class on hover
          }
        });

        // Remove highlight on mouse out
        document.body.addEventListener('mouseout', function(event) {
           const replyMentionLink = event.target.closest('.reply-mention');
           if (replyMentionLink) {
             const targetId = replyMentionLink.getAttribute('href')?.substring(1);
             if (!targetId) return;
             const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
             // Remove highlight immediately on mouseout
             highlightPost(targetPost, false);
           }
        });

        // Highlight on click (for navigation)
        document.body.addEventListener('click', function(event) {
           const replyMentionLink = event.target.closest('.reply-mention');
           if (replyMentionLink && replyMentionLink.getAttribute('href').startsWith('#post-')) {
            const targetId = replyMentionLink.getAttribute('href').substring(1);
            if (!targetId) return;
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            // The browser will navigate, the :target pseudo-class adds scroll margin.
            // We add a temporary visual highlight as well.
            highlightPost(targetPost, true);
            // Note: Preventing default jump and doing smooth scroll + highlight manually is an alternative:
            // event.preventDefault();
            // const targetElement = document.getElementById(targetId);
            // if (targetElement) {
            //    targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
            //    highlightPost(targetPost, true);
            //    window.history.pushState(null, '', '#' + targetId); // Manually update URL hash
            // }
          }
        });


        // --- Initial Highlighting if arriving via hash ---
        if (window.location.hash && window.location.hash.startsWith('#post-')) {
            const targetId = window.location.hash.substring(1);
            const targetPost = document.getElementById(targetId)?.closest('.post, .reply');
            highlightPost(targetPost, true);
        }

      }); // End DOMContentLoaded
    </script>
  </head>
  <body>
    <div class="container">
      <header>
        <?php /* Adjust title based on view */ ?>
        <h1><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code) . '/ - ' . htmlspecialchars($current_channel_display_name) . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></h1>
        <div class="flex-container">
          <?php // Ensure the image path is correct relative to where index.php is run ?>
          <img src="/HDBoard.png" alt="HDBoard Image" style="max-width: 100%; height: auto; max-height: 200px; margin: 0 auto; display: block;">
        </div>
        <nav class="channel-nav">
          <?php
            // Add a "Home" link
            $home_class = $show_board_index ? 'active' : ''; // Highlight Home if on index page
            echo '<a href="./" class="board-index-home-link ' . $home_class . '">Home</a>';

            // Existing channel links
            foreach (ALLOWED_CHANNELS as $channel_code_nav) {
              $display_name = CHANNEL_NAMES[$channel_code_nav] ?? $channel_code_nav;
              // Active class only if NOT showing board index AND current channel matches
              $class = (!$show_board_index && $channel_code_nav === $current_channel_code) ? 'active' : '';
              echo '<a href="./?channel=' . urlencode($channel_code_nav) . '" class="' . $class . '">' . htmlspecialchars($display_name) . '</a>';
            }
          ?>
        </nav>
      </header>

      <?php // Display errors or success messages (use htmlspecialchars for safety)
        if ($post_error): ?>
        <p class="error"><?php echo $post_error; // Already sanitized if it came from DB error ?></p>
      <?php endif;
        // Success messages are usually not shown due to redirects, but kept for debugging
        if ($post_success): ?>
        <p class="success"><?php echo htmlspecialchars($post_success); ?></p>
      <?php endif; ?>

      <?php // --- Main Content Area --- ?>

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
        </ul>
        <hr>
        <p style="text-align: center; color: #aaa;">Select a board to view content.</p>


      <?php else: // --- Channel or Thread View --- ?>

        <?php // NSFW warning (only shown on specific channel views)
          if (!$viewing_thread_id && in_array($current_channel_code, NSFW_CHANNELS)): // Only on board view ?>
          <div class="nsfw-warning" id="nsfw-warning">
            <strong>Warning:</strong> Content on /<?php echo htmlspecialchars($current_channel_code); ?>/ (<?php echo htmlspecialchars($current_channel_display_name); ?>) may be NSFW. Proceed with caution.
            <button class="nsfw-warning-close" id="nsfw-warning-close" title="Close Warning" aria-label="Close Warning">×</button>
          </div>
        <?php endif; ?>


        <?php if ($viewing_thread_id && $thread_op): // --- Thread View --- ?>

          <div class="thread-view-header">
            [<a href="./?channel=<?php echo urlencode($current_channel_code); ?>">Return to /<?php echo htmlspecialchars($current_channel_code); ?>/ - <?php echo htmlspecialchars($current_channel_display_name); ?></a>]
          </div>

          <?php // Reply form at the top in thread view ?>
          <div class="post-form" id="post-form">
            <h4>Reply to Thread No.<?php echo $viewing_thread_id; ?></h4>
            <form action="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $viewing_thread_id; ?>" method="post" enctype="multipart/form-data">
              <input type="hidden" name="thread_id" value="<?php echo $viewing_thread_id; ?>">
              <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
              <table>
                <tr>
                  <th><label for="reply_comment">Comment</label></th>
                  <td><textarea name="comment" id="reply_comment" rows="4" cols="45"></textarea></td>
                </tr>
                <tr>
                  <th><label for="reply_image">File</label></th>
                  <td><input type="file" name="image" id="reply_image" accept="<?php echo implode(',', array_map(function($ext) { return '.' . $ext; }, ALLOWED_EXTENSIONS)); ?>,video/*,audio/*,image/*"></td>
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
            // Display OP Post
            $thread = $thread_op;
            $thread_id = $thread['id'];
            // Use the thread's ID for the post element ID
            $post_element_id = 'post-' . $thread_id; // Unique ID for this post's elements

            $post_media_buttons_html = ''; // Initialize HTML string for media buttons/containers

            // 1. Handle Uploaded File (if exists)
            if ($thread['image']) {
              $uploaded_media_local_path = UPLOADS_DIR . '/' . $thread['image'];
              $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($thread['image']); // Sanitize filename part of URL
              $orig_name = htmlspecialchars($thread['image_orig_name'] ?? $thread['image']); // Sanitize original name for display
              $img_w = $thread['image_w'] ?? '?';
              $img_h = $thread['image_h'] ?? '?';
              $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
              $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
              $uploaded_media_type = get_render_media_type($thread['image']); // Determine type from filename
              $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
              // Ensure uploaded media ID is unique using the post ID
              $media_item_id = $post_element_id . '-uploaded'; // Unique ID for this uploaded media item

              $post_media_buttons_html .= "
                <div class='file-info uploaded-file-info'>
                  <div class='media-toggle'>
                    <button class='show-media-btn'
                        data-media-id='{$media_item_id}'
                        data-media-url='{$uploaded_media_url}'
                        data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                  </div>
                  <span class='file-details'>
                    File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                  </span>
                </div>
                <div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
            }

            // 2. Process Comment for Media Links
            // Get the RAW comment from the database
            $comment_raw_from_db = $thread['comment'];
            // Process it to extract media links and get cleaned text + link media HTML
            // Passes $post_element_id so link IDs are unique per post/reply
            $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
            $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
            $post_media_buttons_html .= $link_media_result['media_html']; // Append HTML for linked media

            // 3. Format the remaining comment text (which now excludes media URLs)
            $formatted_comment = format_comment($cleaned_comment_for_formatting);
            // No truncation needed in thread view

          ?>
          <div class="thread" id="thread-<?php echo $thread_id; ?>">
            <div class="post op" id="<?php echo $post_element_id; ?>"> <?php // Use $post_element_id here ?>
              <p class="post-info">
                <?php if (!empty($thread['subject'])): ?>
                  <span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span>
                <?php endif; ?>
                <span class="name">Anonymous</span>
                <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                <span class="post-id">No.<?php echo $thread_id; ?></span>
                <a href="#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a> <?php // Permalink for OP ?>
              </p>

              <?php echo $post_media_buttons_html; // Output ALL generated media buttons/containers (uploaded + linked) ?>

              <div class="comment">
                <?php echo $formatted_comment; // Output formatted comment (media links removed, other links added) ?>
              </div>
            </div>

            <div class="reply-container">
              <?php
              // Display ALL replies in thread view
              $all_thread_replies = $replies_to_display[$thread_id] ?? [];
              foreach ($all_thread_replies as $reply):
                $reply_id = $reply['id'];
                // Use the reply's ID for the post element ID
                $post_element_id = 'post-' . $reply_id; // Unique ID for this reply's elements

                $reply_media_buttons_html = ''; // Initialize for reply

                // 1. Handle Uploaded File for Reply
                if ($reply['image']) {
                  $uploaded_media_local_path = UPLOADS_DIR . '/' . $reply['image'];
                  $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($reply['image']);
                  $orig_name = htmlspecialchars($reply['image_orig_name'] ?? $reply['image']);
                  $img_w = $reply['image_w'] ?? '?';
                  $img_h = $reply['image_h'] ?? '?';
                  $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
                  $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                  $uploaded_media_type = get_render_media_type($reply['image']);
                  $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
                  // Ensure uploaded media ID is unique using the post ID
                  $media_item_id = $post_element_id . '-uploaded'; // Unique ID for this uploaded media item

                  $reply_media_buttons_html .= "
                    <div class='file-info uploaded-file-info'>
                      <div class='media-toggle'>
                        <button class='show-media-btn'
                            data-media-id='{$media_item_id}'
                            data-media-url='{$uploaded_media_url}'
                            data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                      </div>
                      <span class='file-details'>
                        File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                      </span>
                    </div>
                    <div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
                }

                // 2. Process Comment Media Links for Reply
                $comment_raw_from_db = $reply['comment'];
                 // Passes $post_element_id so link IDs are unique per post/reply
                $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
                $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
                $reply_media_buttons_html .= $link_media_result['media_html'];

                // 3. Format final reply comment
                $formatted_comment = format_comment($cleaned_comment_for_formatting);
                // No truncation in thread view

              ?>
                <div class="reply" id="<?php echo $post_element_id; ?>"> <?php // Use $post_element_id ?>
                  <p class="post-info">
                    <span class="name">Anonymous</span>
                    <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                    <span class="post-id">No.<?php echo $reply_id; ?></span>
                    <a href="#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a> <?php // Permalink for reply ?>
                  </p>

                  <?php echo $reply_media_buttons_html; // Output reply's media buttons ?>

                  <div class="comment">
                    <?php echo $formatted_comment; // Output formatted reply comment ?>
                  </div>
                </div>
              <?php endforeach; ?>
            </div> <?php // End reply-container ?>
          </div><hr>


        <?php else: // --- Board View --- ?>

          <div class="post-form" id="post-form">
            <h2>Post a new thread in /<?php echo htmlspecialchars($current_channel_code); ?>/ - <?php echo htmlspecialchars($current_channel_display_name); ?></h2>
            <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
              <input type="hidden" name="form_type" value="new_thread">
              <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
              <table>
                <tr>
                  <th><label for="subject">Subject</label></th>
                  <td><input type="text" name="subject" id="subject" size="30"></td>
                </tr>
                <tr>
                  <th><label for="comment">Post</label></th>
                  <td><textarea name="comment" id="comment" rows="5" cols="50"></textarea></td>
                </tr>
                <tr>
                  <th><label for="image">File</label></th>
                  <td><input type="file" name="image" id="image" accept="<?php echo implode(',', array_map(function($ext) { return '.' . $ext; }, ALLOWED_EXTENSIONS)); ?>,video/*,audio/*,image/*"></td>
                </tr>
                <tr>
                  <th></th>
                  <td><input type="submit" value="Submit Thread"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB). Comment, File, or Media Link required.</small></td>
                </tr>
              </table>
            </form>
          </div>
          <hr>

          <?php if ($total_threads == 0): // --- Board View, No Threads --- ?>
            <p style="text-align: center; color: #aaa; margin-top: 30px;">No threads in /<?php echo htmlspecialchars($current_channel_code); ?>/ (<?php echo htmlspecialchars($current_channel_display_name); ?>) yet. Be the first!</p>
          <?php else: // --- Board View, With Threads --- ?>

            <?php // Pagination (Top) ?>
            <div class="pagination">
              <?php if ($current_page > 1): ?>
                <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a>
              <?php else: ?>
                <span class="disabled"><< Prev</span>
              <?php endif; ?>
              <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
              <?php if ($current_page < $total_pages): ?>
                <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a>
              <?php else: ?>
                <span class="disabled">Next >></span>
              <?php endif; ?>
            </div>
            <hr>

            <?php foreach ($threads as $thread):
              $thread_id = $thread['id'];
               // Use the thread's ID for the post element ID
              $post_element_id = 'post-' . $thread_id; // Unique ID for OP elements

              $thread_replies_preview = $replies_to_display[$thread_id] ?? [];
              $total_reply_count = $reply_counts[$thread_id] ?? 0;
              $omitted_count = max(0, $total_reply_count - count($thread_replies_preview)); // Ensure non-negative

              $thread_media_buttons_html = ''; // Initialize for thread OP
              $comment_raw_from_db = $thread['comment']; // Get raw comment

              // 1. Handle Uploaded File for Thread OP
              if ($thread['image']) {
                $uploaded_media_local_path = UPLOADS_DIR . '/' . $thread['image'];
                $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($thread['image']);
                $orig_name = htmlspecialchars($thread['image_orig_name'] ?? $thread['image']);
                $img_w = $thread['image_w'] ?? '?';
                $img_h = $thread['image_h'] ?? '?';
                $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
                $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                $uploaded_media_type = get_render_media_type($thread['image']);
                $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
                // Ensure uploaded media ID is unique using the post ID
                $media_item_id = $post_element_id . '-uploaded'; // Unique ID for this uploaded media item


                $thread_media_buttons_html .= "
                  <div class='file-info uploaded-file-info'>
                    <div class='media-toggle'>
                      <button class='show-media-btn'
                          data-media-id='{$media_item_id}'
                          data-media-url='{$uploaded_media_url}'
                          data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                    </div>
                    <span class='file-details'>
                      File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                    </span>
                  </div>
                  <div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
              }

              // 2. Process Comment Media Links for Thread OP
              // Passes $post_element_id so link IDs are unique per post/reply
              $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
              $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
              $thread_media_buttons_html .= $link_media_result['media_html'];

              // 3. Format final comment AND handle truncation for board view OP
              $formatted_comment = format_comment($cleaned_comment_for_formatting);
              $display_comment_html = '';
              // Use mb_strlen on the *cleaned* text (before formatting) for length check
              if (mb_strlen($cleaned_comment_for_formatting) > COMMENT_PREVIEW_LENGTH) {
                  // Truncate the cleaned text *before* formatting
                  $truncated_cleaned_comment = mb_substr($cleaned_comment_for_formatting, 0, COMMENT_PREVIEW_LENGTH);
                  // Format *both* the truncated and full versions
                  $truncated_formatted_comment = format_comment($truncated_cleaned_comment);
                  $full_formatted_comment = $formatted_comment; // Already have full formatted version

                  $display_comment_html = "
                      <div class='comment-truncated'>
                          {$truncated_formatted_comment}... <br>
                          <button class='show-full-text-btn' data-target-id='full-comment-{$post_element_id}'>View Full Text</button>
                      </div>
                      <div id='full-comment-{$post_element_id}' class='comment-full'>
                          {$full_formatted_comment}
                      </div>";
              } else {
                  $display_comment_html = $formatted_comment; // No truncation needed
              }

            ?>
              <div class="thread" id="thread-<?php echo $thread_id; ?>">
                <div class="post op" id="<?php echo $post_element_id; ?>"> <?php // Use $post_element_id ?>
                   <p class="post-info">
                    <?php if (!empty($thread['subject'])): ?>
                      <span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span>
                    <?php endif; ?>
                    <span class="name">Anonymous</span>
                    <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                    <span class="post-id">No.<?php echo $thread_id; ?></span>
                    <span class="reply-link">[<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>" title="View Thread">View</a>]</span>
                    <span class="reply-link">[<a href="#reply-form-<?php echo $thread_id; ?>" onclick="toggleReplyForm(<?php echo $thread_id; ?>); return false;" title="Quick Reply">Reply</a>]</span>
                    <?php if ($total_reply_count > 0): ?>
                      <span class="reply-count">(<?php echo $total_reply_count; ?> replies)</span>
                    <?php endif; ?>
                     <a href="#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a> <?php // Permalink for OP ?>
                  </p>

                  <?php echo $thread_media_buttons_html; // Output OP's media buttons ?>

                  <div class="comment">
                    <?php echo $display_comment_html; // Output truncated or full comment ?>
                  </div>
                </div>

                <?php // Quick Reply Form (hidden initially) ?>
                <div class="reply-form-container" id="reply-form-<?php echo $thread_id; ?>" style="display: none;">
                  <h4>Reply to Thread No.<?php echo $thread_id; ?></h4>
                   <form action="./?channel=<?php echo urlencode($current_channel_code); ?>" method="post" enctype="multipart/form-data">
                    <input type="hidden" name="thread_id" value="<?php echo $thread_id; ?>">
                    <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel_code); ?>">
                    <table>
                      <tr>
                        <th><label for="reply_comment_<?php echo $thread_id; ?>">Comment</label></th>
                        <td><textarea name="comment" id="reply_comment_<?php echo $thread_id; ?>" rows="4" cols="45"></textarea></td>
                      </tr>
                      <tr>
                        <th><label for="reply_image_<?php echo $thread_id; ?>">File</label></th>
                        <td><input type="file" name="image" id="reply_image_<?php echo $thread_id; ?>" accept="<?php echo implode(',', array_map(function($ext) { return '.' . $ext; }, ALLOWED_EXTENSIONS)); ?>,video/*,audio/*,image/*"></td>
                      </tr>
                      <tr>
                        <th></th>
                        <td><input type="submit" value="Submit Reply"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td>
                      </tr>
                    </table>
                  </form>
                </div>

                <div class="reply-container">
                  <?php if ($omitted_count > 0): ?>
                    <p class="omitted-posts">
                      <?php echo $omitted_count; ?> replies omitted.
                      [<a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>">Click here to view the full thread.</a>]
                    </p>
                  <?php endif; ?>

                  <?php // Display preview replies
                  foreach ($thread_replies_preview as $reply):
                    $reply_id = $reply['id'];
                    // Use the reply's ID for the post element ID
                    $post_element_id = 'post-' . $reply_id; // Unique ID for reply elements

                    $reply_media_buttons_html = ''; // Initialize for reply
                    $comment_raw_from_db = $reply['comment']; // Get raw comment

                    // 1. Handle Uploaded File for Reply Preview
                    if ($reply['image']) {
                      $uploaded_media_local_path = UPLOADS_DIR . '/' . $reply['image'];
                      $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($reply['image']);
                      $orig_name = htmlspecialchars($reply['image_orig_name'] ?? $reply['image']);
                      $img_w = $reply['image_w'] ?? '?';
                      $img_h = $reply['image_h'] ?? '?';
                      $file_size = @file_exists($uploaded_media_local_path) ? @filesize($uploaded_media_local_path) : 0;
                      $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                      $uploaded_media_type = get_render_media_type($reply['image']);
                      $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));
                       // Ensure uploaded media ID is unique using the post ID
                       $media_item_id = $post_element_id . '-uploaded'; // Unique ID for this uploaded media item

                      $reply_media_buttons_html .= "
                        <div class='file-info uploaded-file-info'>
                          <div class='media-toggle'>
                            <button class='show-media-btn'
                                data-media-id='{$media_item_id}'
                                data-media-url='{$uploaded_media_url}'
                                data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                          </div>
                          <span class='file-details'>
                            File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                          </span>
                        </div>
                        <div id='media-container-{$media_item_id}' class='media-container' style='display:none;'></div>";
                    }

                    // 2. Process Comment Media Links for Reply Preview
                    // Passes $post_element_id so link IDs are unique per post/reply
                    $link_media_result = process_comment_media_links($comment_raw_from_db, $post_element_id);
                    $cleaned_comment_for_formatting = $link_media_result['cleaned_text'];
                    $reply_media_buttons_html .= $link_media_result['media_html'];

                    // 3. Format final comment AND handle truncation for board view replies
                    $formatted_comment = format_comment($cleaned_comment_for_formatting);
                    $display_comment_html = '';
                    if (mb_strlen($cleaned_comment_for_formatting) > COMMENT_PREVIEW_LENGTH) {
                      $truncated_cleaned_comment = mb_substr($cleaned_comment_for_formatting, 0, COMMENT_PREVIEW_LENGTH);
                      $truncated_formatted_comment = format_comment($truncated_cleaned_comment);
                      $full_formatted_comment = $formatted_comment;

                      $display_comment_html = "
                        <div class='comment-truncated'>
                          {$truncated_formatted_comment}...<br>
                          <button class='show-full-text-btn' data-target-id='full-comment-{$post_element_id}'>View Full Text</button>
                        </div>
                        <div id='full-comment-{$post_element_id}' class='comment-full'>
                          {$full_formatted_comment}
                        </div>";
                    } else {
                      $display_comment_html = $formatted_comment;
                    }

                    ?>
                    <div class="reply" id="<?php echo $post_element_id; ?>"> <?php // Use $post_element_id ?>
                      <p class="post-info">
                        <span class="name">Anonymous</span>
                        <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                        <span class="post-id">No.<?php echo $reply_id; ?></span>
                        <?php // Link to the post within the full thread view ?>
                        <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>#<?php echo $post_element_id; ?>" class="reply-link" title="Link to this post">▶</a>
                      </p>

                      <?php echo $reply_media_buttons_html; // Output reply's media buttons ?>

                      <div class="comment">
                        <?php echo $display_comment_html; // Output truncated or full reply comment ?>
                      </div>
                    </div>
                  <?php endforeach; // End preview replies loop ?>
                </div> <?php // End .reply-container ?>
              </div><hr> <?php // End .thread and add separator ?>
            <?php endforeach; // End threads loop ?>

            <?php // Pagination (Bottom) ?>
            <div class="pagination">
               <?php if ($current_page > 1): ?>
                <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a>
              <?php else: ?>
                <span class="disabled"><< Prev</span>
              <?php endif; ?>
              <span> Page <span class="current-page"><?php echo $current_page; ?></span> / <?php echo $total_pages; ?> </span>
              <?php if ($current_page < $total_pages): ?>
                <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&page=<?php echo $current_page + 1; ?>">Next >></a>
              <?php else: ?>
                <span class="disabled">Next >></span>
              <?php endif; ?>
            </div>

          <?php endif; // End Board View With Threads ?>
        <?php endif; // End Board/Thread Specific Content ?>

      <?php endif; // End $show_board_index Conditional Rendering ?>

    </div> <?php // End .container ?>
  </body>
</html>