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
 * Determines the media type for rendering.
 */
function get_render_media_type($url_or_filename) {
  // YouTube check
  $youtube_regex = '/https?:\/\/(?:www\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/|m\.youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/';
  if (preg_match($youtube_regex, $url_or_filename)) {
    return 'youtube';
  }
  // Extension check
  $extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) return 'image';
  if (in_array($extension, VIDEO_EXTENSIONS)) return 'video';
  if (in_array($extension, AUDIO_EXTENSIONS)) return 'audio';
  return 'unknown';
}

/**
 * Formats comment text for display (Sanitize, NL2BR, Greentext, Reply Links).
 * IMPORTANT: htmlspecialchars IS necessary here for security.
 */
function format_comment($comment) {
  $comment = (string) ($comment ?? '');

  // 1. Sanitize HTML to prevent XSS. THIS IS CRITICAL.
  $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');

  // 2. Convert newlines to <br>
  $comment = nl2br($comment);

  // 3. Greentext (handles start of line or after <br />)
  $comment = preg_replace('/(^<br \/>|^\s*)(>[^>].*?)$/m', '$1<span class="greentext">$2</span>', $comment);
  $comment = preg_replace('/(^\s*)(>[^>].*?)$/m', '$1<span class="greentext">$2</span>', $comment);

  // 4. Reply Links (works on >> after sanitization which turns > into >)
  $comment = preg_replace('/>>(\d+)/', '<a href="#post-$1" class="reply-mention">>>$1</a>', $comment);

  return $comment;
}

/**
 * Finds URLs, separates media links, generates media buttons, returns cleaned text.
 */
function process_comment_media_links($text, $post_element_id) {
  $media_html = '';
  $cleaned_text = $text;
  $link_counter = 0;
  // Regex to find URLs (avoids matching inside existing tags like src/href)
  $url_regex = '/(?<!src=["\'])(?<!href=["\'])(https?|ftp):\/\/[^\s<>"]+/i';

  if (preg_match_all($url_regex, $text, $matches, PREG_OFFSET_CAPTURE)) {
    $matches = array_reverse($matches[0]); // Process in reverse offset order

    foreach ($matches as $match) {
      $url = $match[0];
      $offset = $match[1];
      $render_type = get_render_media_type($url);

      if ($render_type !== 'unknown') {
        $link_counter++;
        $media_id = $post_element_id . '-link-' . $link_counter;
        $safe_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8'); // Sanitize URL for display/attributes

        $button_text = 'View Media';
        if ($render_type === 'image') $button_text = 'View Image';
        elseif ($render_type === 'video') $button_text = 'View Video';
        elseif ($render_type === 'audio') $button_text = 'View Audio';
        elseif ($render_type === 'youtube') $button_text = 'View YouTube';

        // Prepend button/container HTML
        $media_html = "
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
          <div id='media-container-{$media_id}' class='media-container' style='display:none;'></div>" . $media_html;

        // Remove the raw URL from the text
        $cleaned_text = substr_replace($cleaned_text, '', $offset, strlen($url));
      }
    }
  }

  return ['cleaned_text' => $cleaned_text, 'media_html' => $media_html];
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
  $comment = trim($_POST['comment'] ?? '');
  $subject = trim($_POST['subject'] ?? ''); // Only for new threads
  $thread_id = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT); // For replies
  $posted_channel_code = trim($_POST['channel'] ?? ''); // The short code submitted from the form

  // --- Basic Validation (ensure channel code from form matches current context if possible) ---
  // If replying, the $thread_id tells us the context.
  // If new thread, the $posted_channel_code MUST match the $current_channel_code from the URL.
  if (!$thread_id && $posted_channel_code !== $current_channel_code) {
    $post_error = "Channel mismatch detected. Please post from the correct board page.";
  } else {
    // --- Proceed with existing validation ---
    $temp_media_check = process_comment_media_links($comment, 'temp');
    $has_text = !empty($comment);
    $has_media_links = !empty($temp_media_check['media_html']);
    $has_file = isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE;

    if (!$has_text && !$has_media_links && !$has_file) {
      $post_error = "A post content, a file, or media links are required.";
    } elseif (mb_strlen($comment) > 4000) {
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

          if ($thread_id) { // Posting a Reply
            // Verify thread exists and get its channel (important for redirect)
            $stmt = $db->prepare("SELECT id, channel FROM threads WHERE id = ?");
            $stmt->execute([$thread_id]);
            $thread_data = $stmt->fetch();

            if ($thread_data) {
              // Ensure reply is posted to the correct channel context (based on thread's channel)
              if ($thread_data['channel'] !== $current_channel_code) {
                // This check is redundant if the initial POST check works, but good safeguard
                $db->rollBack();
                $post_error = "Attempting to reply to a thread from the wrong channel page.";
              } else {
                $stmt = $db->prepare("INSERT INTO replies (thread_id, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$thread_id, $comment, $image_filename, $image_orig_name, $image_w, $image_h]);
                $new_post_id = $db->lastInsertId();

                $stmt = $db->prepare("UPDATE threads SET last_reply_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$thread_id]);

                $db->commit();
                // Success message isn't strictly needed because we redirect immediately
                // $post_success = "Reply #{$new_post_id} posted successfully.";

                // Redirect back to the thread view including the new reply anchor
                // Use the THREAD'S channel code for the redirect URL
                $redirect_params = ['channel' => $thread_data['channel'], 'thread' => $thread_id];
                $redirect_url = './?' . http_build_query($redirect_params) . '&ts=' . time() . '#post-' . $new_post_id;
                header("Location: " . $redirect_url);
                exit; // IMPORTANT: Stop script execution after sending header
              }

            } else {
              $post_error = "Thread not found.";
              $db->rollBack();
            }

          } else { // Posting a New Thread
            // Use the validated $current_channel_code (which matched $posted_channel_code)
            $stmt = $db->prepare("INSERT INTO threads (channel, subject, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$current_channel_code, $subject, $comment, $image_filename, $image_orig_name, $image_w, $image_h]);
            $new_post_id = $db->lastInsertId();

            $db->commit();
            // $post_success = "Thread #{$new_post_id} created successfully."; // No longer displayed due to redirect

            // --- ADDED: Redirect after successful NEW THREAD post ---
            // Redirect back to the board view of the current channel to prevent resubmission
            $redirect_params = ['channel' => $current_channel_code];
            // Add cache buster (optional, but good practice)
            $redirect_url = './?' . http_build_query($redirect_params) . '&ts=' . time();
            header("Location: " . $redirect_url);
            exit; // IMPORTANT: Stop script execution after sending header
            // --- END ADDED REDIRECT ---
          }

        } catch (PDOException $e) {
          $db->rollBack();
          error_log("Database Post Error: " . $e->getMessage());
          $post_error = "Database Error: " . $e->getMessage();
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
        max-width: calc(100% - 20px);
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

      /* File/Media Info & Toggle */
      .file-info {
        font-size: 0.9em;
        color: #ccc; /* Light grey for file details */
        margin-bottom: 8px;
        display: flex;
        align-items: flex-start;
        flex-wrap: wrap;
        gap: 10px;
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
        line-height: normal;
        text-transform: none;
        white-space: normal;
      }
      .file-info .media-toggle button.show-media-btn:hover {
        background-color: var(--button-hover-bg);
      }
      .file-details {
        flex-grow: 1;
        margin-top: 5px; /* Align text baseline slightly better */
        word-break: break-all; /* Allow long filenames/links to break */
      }
      .file-details a {
        color: var(--link-color);
        text-decoration: underline;
      }
      .file-details a:hover {
        color: var(--link-hover);
      }

      /* Media Container */
      .media-container {
        margin-top: 8px;
        margin-bottom: 10px;
        border: 1px dashed var(--border-color);
        padding: 5px;
        display: none; /* Hidden by default */
        max-width: 100%;
        box-sizing: border-box;
        overflow: hidden;
        background-color: var(--bg-color); /* Ensure background for padding */
      }
      .media-container img,
      .media-container video,
      .media-container audio,
      .media-container iframe {
        display: block;
        max-width: 100%;
        height: auto;
        margin: 0 auto;
        background-color: #000; /* Black bg for media loading */
      }
       .media-container video {
         /* Consider adding controls styling if needed */
       }
      .media-container audio {
        width: 100%;
        /* Add filter to make controls match dark theme if possible/needed */
        /* filter: invert(1) hue-rotate(180deg); */ /* Basic inversion, might need tweaking */
      }
      /* Aspect Ratio Containers */
      .youtube-embed-container, .video-embed-container {
        margin: 10px 0;
        position: relative;
        padding-bottom: 56.25%; /* 16:9 */
        height: 0;
        overflow: hidden;
        max-width: 100%;
        background: #000;
      }
      .youtube-embed-container iframe,
      .video-embed-container video {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        border: none;
      }

      /* Comment Styling */
      .comment {
        margin-top: 10px;
        line-height: 1.5;
        overflow-wrap: break-word;
        word-break: break-word;
        color: var(--text-color); /* Ensure comment text uses main text color */
      }
      .comment-truncated { display: block; }
      .comment-full { display: none; }
      .show-full-text-btn {
        padding: 2px 5px;
        font-size: 0.8em;
        cursor: pointer;
        margin-left: 5px;
        background-color: var(--button-bg);
        border: 1px solid var(--input-border);
        border-radius: 3px;
        color: var(--button-text);
      }
      .show-full-text-btn:hover { background-color: var(--button-hover-bg); }

      .greentext { color: var(--greentext-color); }
      .reply-mention {
        color: var(--reply-mention-color);
        text-decoration: underline;
        font-weight: bold;
      }
      .reply-mention:hover { color: var(--link-hover); }

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
        scroll-margin-top: 20px; /* Adjust as needed */
        /* Add highlight on target */
        /* Maybe handled by JS hover effect now, but could add a subtle border */
         /* border-left: 3px solid var(--accent-red); */
         /* padding-left: calc(12px - 3px); /* Adjust padding to compensate */
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

        .file-info { flex-direction: column; align-items: flex-start; }
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
        .post-info .time, .post-info .post-id, .post-info .reply-link { font-size: 1em; margin-left: 4px; }

        .pagination { font-size: 1em; }
        .pagination a, .pagination span { padding: 3px 6px; }
        .thread-view-header { font-size: 1em; }
      }

      @media (min-width: 768px) {
        .post-form th { width: 100px; text-align: right; display: table-cell; }
        .post-form td { display: table-cell; }
        .reply-form-container th { width: 80px; }

        .file-info { flex-direction: row; align-items: flex-start; }
        .file-info .media-toggle { margin-bottom: 0; }
        .file-info .file-details { margin-top: 5px; }

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
          }
        }
      }

      // Toggle media visibility and load content dynamically
      function toggleMedia(button, mediaId) {
        const mediaContainer = document.getElementById('media-container-' + mediaId);
        if (!mediaContainer) return;

        const isHidden = (mediaContainer.style.display === 'none' || mediaContainer.style.display === '');
        const mediaUrl = button.dataset.mediaUrl;
        const mediaType = button.dataset.mediaType;

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
            mediaContainer.innerHTML = ''; // Clear previous
            mediaContainer.dataset.loadedUrl = mediaUrl; // Mark as loaded

            let mediaElementHTML = '';
            if (IMAGE_TYPES.includes(mediaType)) {
              mediaElementHTML = `<a href="${mediaUrl}" target="_blank"><img src="${mediaUrl}" alt="Media Image"></a>`;
            } else if (VIDEO_TYPES.includes(mediaType)) {
              mediaElementHTML = `<div class="video-embed-container"><video src="${mediaUrl}" controls playsinline preload="metadata"></video></div>`;
            } else if (AUDIO_TYPES.includes(mediaType)) {
              mediaElementHTML = `<audio src="${mediaUrl}" controls preload="metadata"></audio>`;
            } else if (mediaType === YOUTUBE_TYPE) {
              const youtubeRegexMatch = mediaUrl.match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|m\.youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/);
              const videoId = (youtubeRegexMatch && youtubeRegexMatch[1]) ? youtubeRegexMatch[1] : null;
              if (videoId) {
                const embedUrl = `https://www.youtube.com/embed/${videoId}`;
                mediaElementHTML = `<div class="youtube-embed-container"><iframe src="${embedUrl}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen loading="lazy"></iframe></div>`;
              } else {
                mediaElementHTML = '<span>Failed to embed YouTube video (Invalid URL).</span>';
              }
            } else {
              mediaElementHTML = '<span>Unsupported media type: ' + mediaType + '</span>';
            }
            mediaContainer.innerHTML = mediaElementHTML;
          }
        } else {
          // Hide container and reset button text
          mediaContainer.style.display = 'none';
          button.textContent = viewButtonText;

          // Stop media playback when hiding
          mediaContainer.querySelectorAll('video, audio, iframe').forEach(mediaElement => {
            if (typeof mediaElement.pause === 'function' && !mediaElement.paused) {
              mediaElement.pause();
            }
            // Attempt to stop YouTube iframe
            if (mediaElement.tagName === 'IFRAME' && mediaElement.src.includes('youtube.com/embed') && mediaElement.contentWindow) {
              mediaElement.contentWindow.postMessage('{"event":"command","func":"pauseVideo","args":""}', '*');
            }
          });
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
        // Attach listeners to dynamic elements

        // Media toggle buttons
        document.body.addEventListener('click', function(event) {
          if (event.target.matches('.show-media-btn')) {
            const mediaId = event.target.dataset.mediaId;
            if (mediaId) {
              toggleMedia(event.target, mediaId);
            }
          }
        });

        // Text expansion buttons
        document.body.addEventListener('click', function(event) {
          if (event.target.matches('.show-full-text-btn')) {
            const fullTextId = event.target.dataset.targetId;
             if (fullTextId) {
              toggleFullText(event.target, fullTextId);
            }
          }
        });

        // NSFW Warning Close Button
        const nsfwWarning = document.getElementById('nsfw-warning');
        const nsfwCloseBtn = document.getElementById('nsfw-warning-close');
        if (nsfwWarning && nsfwCloseBtn) {
          nsfwCloseBtn.addEventListener('click', function() {
            nsfwWarning.style.display = 'none';
          });
        }

        // Reply mention hover effect
        document.body.addEventListener('mouseover', function(event) {
          if (event.target.matches('.reply-mention')) {
            const targetId = event.target.getAttribute('href')?.substring(1);
            if (!targetId) return;
            const targetPost = document.getElementById(targetId);
            if (targetPost) {
              targetPost.style.backgroundColor = '#404050'; // Darker highlight
              targetPost.style.borderColor = '#7aa2f7'; // Link color border
              targetPost.dataset.originalBg = targetPost.style.backgroundColor; // Store for mouseout
              targetPost.dataset.originalBorder = targetPost.style.borderColor;
            }
          }
        });
        document.body.addEventListener('mouseout', function(event) {
          if (event.target.matches('.reply-mention')) {
             const targetId = event.target.getAttribute('href')?.substring(1);
             if (!targetId) return;
             const targetPost = document.getElementById(targetId);
             if (targetPost) {
               // Reset styles - assumes default is set by CSS, don't rely on dataset if complex
               targetPost.style.backgroundColor = '';
               targetPost.style.borderColor = '';
             }
          }
        });

      }); // End DOMContentLoaded
    </script>
  </head>
  <body>
    <div class="container">
      <header>
        <?php /* Adjust title based on view */ ?>
        <h1><?php echo $show_board_index ? 'HDBoard - Board Index' : ('/' . htmlspecialchars($current_channel_code) . '/ - ' . htmlspecialchars($current_channel_display_name) . ($viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : '')); ?></h1>
        <div class="flex-container">
          <img src="/HDBoard.png" alt="HDBoard Image">
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
        <p class="error"><?php echo htmlspecialchars($post_error); ?></p>
      <?php endif;
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
        if (in_array($current_channel_code, NSFW_CHANNELS)): ?>
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
          $post_element_id = 'post-' . $thread_id;

          $post_media_buttons_html = '';
          $cleaned_comment_content_raw = $thread['comment'];

          // Handle Uploaded File
          if ($thread['image']) {
            $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($thread['image']); // Sanitize filename part of URL
            $orig_name = htmlspecialchars($thread['image_orig_name'] ?? $thread['image']); // Sanitize original name for display
            $img_w = $thread['image_w'] ?? '?';
            $img_h = $thread['image_h'] ?? '?';
            $file_size = @filesize(UPLOADS_DIR . '/' . $thread['image']);
            $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
            $uploaded_media_type = get_render_media_type($thread['image']);
            $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));

            $post_media_buttons_html .= "
              <div class='file-info uploaded-file-info'>
                <div class='media-toggle'>
                  <button class='show-media-btn'
                      data-media-id='{$post_element_id}-uploaded'
                      data-media-url='{$uploaded_media_url}'
                      data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                </div>
                <span class='file-details'>
                  File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                </span>
              </div>
              <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'></div>";
          }

          // Process Comment Media Links
          $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
          $cleaned_comment_content_raw = $link_media_result['cleaned_text'];
          $post_media_buttons_html .= $link_media_result['media_html'];

          // Format final comment (already sanitized inside format_comment)
          $formatted_comment = format_comment($cleaned_comment_content_raw);

          ?>
          <div class="thread" id="thread-<?php echo $thread_id; ?>">
            <div class="post op" id="post-<?php echo $thread_id; ?>">
              <p class="post-info">
                <?php if (!empty($thread['subject'])): ?>
                  <span class="subject"><?php echo htmlspecialchars($thread['subject']); ?></span> <?php // Sanitize subject ?>
                <?php endif; ?>
                <span class="name">Anonymous</span>
                <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($thread['created_at'])); ?></span>
                <span class="post-id">No.<?php echo $thread_id; ?></span>
              </p>
              <?php echo $post_media_buttons_html; // Output generated media buttons/containers ?>
              <div class="comment">
                <?php echo $formatted_comment; // Output formatted comment (already sanitized) ?>
              </div>
            </div>

            <div class="reply-container">
              <?php
              // Display ALL replies in thread view
              $all_thread_replies = $replies_to_display[$thread_id] ?? [];
              foreach ($all_thread_replies as $reply):
                $reply_id = $reply['id'];
                $post_element_id = 'post-' . $reply_id;

                $reply_media_buttons_html = '';
                $cleaned_comment_content_raw = $reply['comment'];

                // Handle Uploaded File for Reply
                if ($reply['image']) {
                  $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($reply['image']);
                  $orig_name = htmlspecialchars($reply['image_orig_name'] ?? $reply['image']);
                  $img_w = $reply['image_w'] ?? '?';
                  $img_h = $reply['image_h'] ?? '?';
                  $file_size = @filesize(UPLOADS_DIR . '/' . $reply['image']);
                  $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                  $uploaded_media_type = get_render_media_type($reply['image']);
                  $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));

                  $reply_media_buttons_html .= "
                    <div class='file-info uploaded-file-info'>
                      <div class='media-toggle'>
                        <button class='show-media-btn'
                            data-media-id='{$post_element_id}-uploaded'
                            data-media-url='{$uploaded_media_url}'
                            data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                      </div>
                      <span class='file-details'>
                        File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                      </span>
                    </div>
                    <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'></div>";
                }

                // Process Comment Media Links for Reply
                $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
                $cleaned_comment_content_raw = $link_media_result['cleaned_text'];
                $reply_media_buttons_html .= $link_media_result['media_html'];

                // Format final reply comment
                $formatted_comment = format_comment($cleaned_comment_content_raw);

              ?>
                <div class="reply" id="post-<?php echo $reply_id; ?>">
                  <p class="post-info">
                    <span class="name">Anonymous</span>
                    <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                    <span class="post-id">No.<?php echo $reply_id; ?></span>
                    <a href="#post-<?php echo $reply_id; ?>" class="reply-link" title="Link to this post">▶</a>
                  </p>
                  <?php echo $reply_media_buttons_html; ?>
                  <div class="comment">
                    <?php echo $formatted_comment; // No truncation in thread view ?>
                  </div>
                </div>
              <?php endforeach; ?>
            </div>
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
                  <td><input type="submit" value="Submit Thread"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB). Post Content or File required.</small></td>
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
              $post_element_id = 'post-' . $thread_id;

              $thread_replies_preview = $replies_to_display[$thread_id] ?? [];
              $total_reply_count = $reply_counts[$thread_id] ?? 0;
              $omitted_count = max(0, $total_reply_count - count($thread_replies_preview)); // Ensure non-negative

              $thread_media_buttons_html = '';
              $cleaned_comment_content_raw = $thread['comment'];

              // Handle Uploaded File for Thread OP
              if ($thread['image']) {
                $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($thread['image']);
                $orig_name = htmlspecialchars($thread['image_orig_name'] ?? $thread['image']);
                $img_w = $thread['image_w'] ?? '?';
                $img_h = $thread['image_h'] ?? '?';
                $file_size = @filesize(UPLOADS_DIR . '/' . $thread['image']);
                $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                $uploaded_media_type = get_render_media_type($thread['image']);
                $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));

                $thread_media_buttons_html .= "
                  <div class='file-info uploaded-file-info'>
                    <div class='media-toggle'>
                      <button class='show-media-btn'
                          data-media-id='{$post_element_id}-uploaded'
                          data-media-url='{$uploaded_media_url}'
                          data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                    </div>
                    <span class='file-details'>
                      File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                    </span>
                  </div>
                  <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'></div>";
              }

              // Process Comment Media Links for Thread OP
              $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
              $cleaned_comment_content_raw = $link_media_result['cleaned_text'];
              $thread_media_buttons_html .= $link_media_result['media_html'];

              // Format final comment
              $formatted_comment = format_comment($cleaned_comment_content_raw);

              // Handle text truncation for board view OP
              $display_comment_html = '';
              // Use mb_strlen on the raw text *before* formatting for length check
              if (mb_strlen($cleaned_comment_content_raw) > COMMENT_PREVIEW_LENGTH) {
                // Truncate raw text, then format *both* parts
                $truncated_raw_comment = mb_substr($cleaned_comment_content_raw, 0, COMMENT_PREVIEW_LENGTH);
                $truncated_formatted_comment = format_comment($truncated_raw_comment); // Format truncated part
                $full_formatted_comment = $formatted_comment; // Already have full formatted comment

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
                <div class="post op" id="post-<?php echo $thread_id; ?>">
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
                  </p>
                  <?php echo $thread_media_buttons_html; ?>
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
                    $post_element_id = 'post-' . $reply_id;

                    $reply_media_buttons_html = '';
                    $cleaned_comment_content_raw = $reply['comment'];

                    // Handle Uploaded File for Reply Preview
                    if ($reply['image']) {
                      $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($reply['image']);
                      $orig_name = htmlspecialchars($reply['image_orig_name'] ?? $reply['image']);
                      $img_w = $reply['image_w'] ?? '?';
                      $img_h = $reply['image_h'] ?? '?';
                      $file_size = @filesize(UPLOADS_DIR . '/' . $reply['image']);
                      $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                      $uploaded_media_type = get_render_media_type($reply['image']);
                      $view_button_text = ($uploaded_media_type == 'image') ? 'View Image' : (($uploaded_media_type == 'video') ? 'View Video' : (($uploaded_media_type == 'audio') ? 'View Audio' : 'View File'));

                      $reply_media_buttons_html .= "
                        <div class='file-info uploaded-file-info'>
                          <div class='media-toggle'>
                            <button class='show-media-btn'
                                data-media-id='{$post_element_id}-uploaded'
                                data-media-url='{$uploaded_media_url}'
                                data-media-type='{$uploaded_media_type}'>{$view_button_text}</button>
                          </div>
                          <span class='file-details'>
                            File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}" . (($img_w != '?') ? ", {$img_w}x{$img_h}" : "") . ")
                          </span>
                        </div>
                        <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'></div>";
                    }

                    // Process Comment Media Links for Reply Preview
                    $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
                    $cleaned_comment_content_raw = $link_media_result['cleaned_text'];
                    $reply_media_buttons_html .= $link_media_result['media_html'];

                    // Format final comment
                    $formatted_comment = format_comment($cleaned_comment_content_raw);

                    // Handle text truncation for board view replies
                    $display_comment_html = '';
                    if (mb_strlen($cleaned_comment_content_raw) > COMMENT_PREVIEW_LENGTH) {
                      $truncated_raw_comment = mb_substr($cleaned_comment_content_raw, 0, COMMENT_PREVIEW_LENGTH);
                      $truncated_formatted_comment = format_comment($truncated_raw_comment);
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
                    <div class="reply" id="post-<?php echo $reply_id; ?>">
                      <p class="post-info">
                        <span class="name">Anonymous</span>
                        <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                        <span class="post-id">No.<?php echo $reply_id; ?></span>
                        <a href="./?channel=<?php echo urlencode($current_channel_code); ?>&thread=<?php echo $thread_id; ?>#post-<?php echo $reply_id; ?>" class="reply-link" title="Link to this post">▶</a>
                      </p>
                      <?php echo $reply_media_buttons_html; ?>
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