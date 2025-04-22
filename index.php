<?php

// --- Configuration ---
define('DB_FILE', __DIR__ . '/board.db'); // Database file in the same directory as the script
define('UPLOADS_DIR', __DIR__ . '/uploads'); // Uploads directory in the same directory
define('UPLOADS_URL_PATH', 'uploads'); // Relative web path to uploads dir
define('MAX_FILE_SIZE', 20 * 1024 * 1024); // Increased to 20 MB
// Add more allowed extensions if you expect video/audio uploads
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'webm', 'mp3', 'wav', 'ogg', 'avi', 'mov', 'flv', 'wmv']); // Added more common video types
// Define supported video and audio extensions for HTML tags
define('VIDEO_EXTENSIONS', ['mp4', 'webm', 'avi', 'mov', 'flv', 'wmv']);
define('AUDIO_EXTENSIONS', ['mp3', 'wav', 'ogg']);

// Define your channels here. The first one will be the default if none is specified in the URL.
define('ALLOWED_CHANNELS', ['b', 'tech', 'anime', 'games', 'music', 'politika', 'art', 'food', 'travel', 'random']);
define('THREADS_PER_PAGE', 10); // How many threads per page in board view
define('REPLIES_PREVIEW_COUNT', 6); // How many replies to show on the main page preview
define('COMMENT_PREVIEW_LENGTH', 1000); // Max characters to display before truncation


// --- Initialization & DB Setup ---
ini_set('display_errors', 1); // Show errors during development - DISABLE IN PRODUCTION
error_reporting(E_ALL);

// Ensure uploads directory exists and is writable
if (!is_dir(UPLOADS_DIR)) {
  if (!mkdir(UPLOADS_DIR, 0775, true)) {
    // Log the error instead of dying in a production environment
    error_log("Error: Could not create uploads directory at " . UPLOADS_DIR);
    die("Error: Could not create uploads directory. Please create it manually and ensure it's writable by the web server.");
  }
}
if (!is_writable(UPLOADS_DIR)) {
  error_log("Error: Uploads directory is not writable: " . UPLOADS_DIR);
  die("Error: The uploads directory '" . UPLOADS_DIR . "' is not writable by the web server.");
}

try {
  $db = new PDO('sqlite:' . DB_FILE);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Throw exceptions on error
  $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC); // Fetch assoc arrays

  // Create tables if they don't exist (schema defined in previous step)
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

  // Add channel column if it doesn't exist (for backward compatibility)
  try {
    $columns = $db->query("PRAGMA table_info(threads)")->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array('channel', $columns)) {
      $db->exec("ALTER TABLE threads ADD COLUMN channel TEXT NOT NULL DEFAULT '" . ALLOWED_CHANNELS[0] . "'");
    }
  } catch (PDOException $e) {
    error_log("Database ALTER TABLE error: " . $e->getMessage());
    echo "<p class='error'>Warning: Could not add 'channel' column to 'threads' table. Error: " . htmlspecialchars($e->getMessage()) . "</p>";
  }


} catch (PDOException $e) {
  error_log("Database Connection Error: " . $e->getMessage());
  die("Database Connection Error: " . $e->getMessage());
}

// --- Functions ---

/**
 * Handles file uploads.
 * @param string $file_input_name The name of the file input field (e.g., 'image').
 * @return array An associative array with 'success' (bool) and optional 'error' (string) or upload details.
 */
function handle_upload($file_input_name) {
  // Assumes only one file input with this name based on current HTML/DB
  if (!isset($_FILES[$file_input_name]) || $_FILES[$file_input_name]['error'] === UPLOAD_ERR_NO_FILE) {
    return ['success' => false]; // No file was uploaded
  }

  $file = $_FILES[$file_input_name];

  if ($file['error'] !== UPLOAD_ERR_OK) {
    // Handle upload errors
    switch ($file['error']) {
      case UPLOAD_ERR_INI_SIZE:
      case UPLOAD_ERR_FORM_SIZE:
        return ['error' => 'File is too large (Server limit).'];
      case UPLOAD_ERR_PARTIAL:
        return ['error' => 'File was only partially uploaded.'];
      case UPLOAD_ERR_NO_TMP_DIR:
        return ['error' => 'Missing temporary folder for uploads.'];
      case UPLOAD_ERR_CANT_WRITE:
        return ['error' => 'Failed to write file to disk. Check server permissions.'];
      case UPLOAD_ERR_EXTENSION:
        return ['error' => 'A PHP extension stopped the file upload.'];
      default:
        return ['error' => 'Unknown upload error (Code: ' . $file['error'] . ').'];
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

  // Get image dimensions for image types
  $img_w = null;
  $img_h = null;
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
    $image_size = @getimagesize($file['tmp_name']);
    if ($image_size !== false) {
      $img_w = $image_size[0] ?? null;
      $img_h = $image_size[1] ?? null;
    }
  }
  // Note: Getting dimensions for video/audio typically requires external libraries (like ffprobe) which is outside simple PHP scope.

  // Create a unique filename
  $new_filename = uniqid() . time() . '.' . $extension;
  $destination = UPLOADS_DIR . '/' . $new_filename;

  if (move_uploaded_file($file['tmp_name'], $destination)) {
    // Double-check if the file actually exists after moving
    if (!file_exists($destination)) {
      error_log("Failed to confirm uploaded file existence after move: " . $destination);
      return ['error' => 'Failed to confirm uploaded file existence after move.'];
    }
    return [
      'success' => true,
      'filename' => $new_filename,
      'orig_name' => basename($file['name']),
      'width' => $img_w, // Will be null for non-image types
      'height' => $img_h // Will be null for non-image types
    ];
  } else {
    if (!is_writable(UPLOADS_DIR)) {
      error_log("Upload destination directory is not writable: " . UPLOADS_DIR);
      return ['error' => 'Upload destination directory is not writable.'];
    }
    error_log("Failed to move uploaded file to " . $destination . ". Source: " . $file['tmp_name']);
    return ['error' => 'Failed to move uploaded file. Possible disk space issue or incorrect permissions.'];
  }
}

/**
 * Determines the media type for rendering based on file extension or URL pattern.
 * Returns 'image', 'video', 'audio', 'youtube', or 'unknown'.
 * @param string $url_or_filename The URL or filename.
 * @return string
 */
function get_render_media_type($url_or_filename) {
  // Check for YouTube pattern first
  $youtube_regex = '/https?:\/\/(?:www\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|youtu\.be\/|m\.youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/';
  if (preg_match($youtube_regex, $url_or_filename)) {
    return 'youtube';
  }

  // Otherwise, check extension
  $extension = strtolower(pathinfo($url_or_filename, PATHINFO_EXTENSION));
  if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
    return 'image';
  } elseif (in_array($extension, VIDEO_EXTENSIONS)) {
    return 'video';
  } elseif (in_array($extension, AUDIO_EXTENSIONS)) {
    return 'audio';
  }
  return 'unknown';
}


/**
 * Formats comment text for display (HTML entities, newlines, greentext, reply links).
 * Note: Media/YouTube links are REMOVED from the text BEFORE this step.
 * @param string|null $comment The raw comment text (after media links removed).
 * @return string The formatted HTML comment.
 */
function format_comment($comment) {
  // Ensure comment is a string and handle null/empty
  $comment = (string) ($comment ?? '');

  // 1. Sanitize HTML to prevent XSS
  $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');

  // 2. Convert newlines to <br> tags
  $comment = nl2br($comment);

  // 3. Basic Greentext (> at the start of a line)
  // Use word boundaries to avoid matching things like >> as greentext lines
  // Apply after nl2br
  $comment = preg_replace('/(^<br \/>|^\s*)(>.*?)$/m', '$1<span class="greentext">$2</span>', $comment);
  $comment = preg_replace('/(^\s*)(>.*?)$/m', '$1<span class="greentext">$2</span>', $comment); // Handle case without preceding <br/>

  // 4. Basic Reply Links (>> followed by numbers)
  // This needs to happen *after* htmlspecialchars turns >> into >>
  $comment = preg_replace('/>>(>)*(\d+)/', '<a href="#post-$2" class="reply-mention">>>$2</a>', $comment); // Added >* to handle already htmlspecialchared text

  // 5. Note: Media links are already removed from the text before this step.

  return $comment;
}

/**
 * Finds URLs in text, determines if they are media links (including YouTube),
 * removes them from the text, and generates HTML for corresponding media buttons/containers.
 * Returns the cleaned text and the generated media HTML.
 * @param string $text The input text (comment).
 * @param string $post_element_id The ID prefix for media containers (e.g., 'post-123').
 * @return array An associative array with 'cleaned_text' and 'media_html'.
 */
function process_comment_media_links($text, $post_element_id) {
  $media_html = '';
  $cleaned_text = $text;
  $link_counter = 0; // Counter for unique media IDs within a post's links

  // Regex to find URLs in text (basic)
  // Allows for http, https, ftp, and domain.tld/path
  // Added lookbehind to avoid matching URLs inside img/a tags etc.
  $url_regex = '/(?<!src=["\'])(?<!href=["\'])(https?|ftp):\/\/[^\s<>"]+/i';

  // Find all potential URLs
  if (preg_match_all($url_regex, $text, $matches, PREG_OFFSET_CAPTURE)) {
    // Process matches in reverse order of offset to avoid issues with replacements
    $matches = array_reverse($matches[0]);

    foreach ($matches as $match) {
      $url = $match[0];
      $offset = $match[1];

      $render_type = get_render_media_type($url);

      if ($render_type !== 'unknown') {
        // This URL is a media link (or YouTube)
        $link_counter++;
        $media_id = $post_element_id . '-link-' . $link_counter; // Unique ID for this link's media
        $safe_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');

        $button_text = 'View Media';
        if ($render_type === 'image') $button_text = 'View Image';
        elseif ($render_type === 'video') $button_text = 'View Video';
        elseif ($render_type === 'audio') $button_text = 'View Audio';
        elseif ($render_type === 'youtube') $button_text = 'View YouTube';


        $media_html = "
          <div class='file-info comment-link-info'>
            <div class='media-toggle'>
              <button class='show-media-btn btn btn-sm btn-outline-info'
                  data-media-id='{$media_id}'
                  data-media-url='{$safe_url}'
                  data-media-type='{$render_type}'>{$button_text}</button>
            </div>
            <span class='file-details'>
              Link: <a href='{$safe_url}' target='_blank' rel='noopener noreferrer'>{$safe_url}</a>
            </span>
          </div>
          <div id='media-container-{$media_id}' class='media-container' style='display:none;'>
            " . "<!-- Media dynamically loaded here -->" . "
          </div>" . $media_html; // Prepend to keep order


        // Remove the raw URL from the cleaned text using substring replacement based on offset
        $cleaned_text = substr_replace($cleaned_text, '', $offset, strlen($url));

      }
    }
  }

  return [
    'cleaned_text' => $cleaned_text,
    'media_html' => $media_html
  ];
}


// --- Determine Current Channel ---
$current_channel = ALLOWED_CHANNELS[0]; // Default channel
if (isset($_GET['channel']) && in_array($_GET['channel'], ALLOWED_CHANNELS)) {
  $current_channel = $_GET['channel'];
}

// --- Determine if viewing a specific thread ---
$viewing_thread_id = filter_input(INPUT_GET, 'thread', FILTER_VALIDATE_INT);

// --- Handle Post Request ---
$post_error = null;
$post_success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
  $comment = trim($_POST['comment'] ?? '');
  $subject = trim($_POST['subject'] ?? ''); // Only for new threads
  $thread_id = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT); // For replies
  // The channel is determined by the form's hidden input, which reflects the page the user was on
  $posted_channel = trim($_POST['channel'] ?? '');

  // Check if comment has text or media links or file
  $temp_media_check = process_comment_media_links($comment, 'temp'); // Use a temporary ID
  $has_media_links = !empty($temp_media_check['media_html']);

  if (empty($comment) && (!$has_media_links) && (!isset($_FILES['image']) || $_FILES['image']['error'] == UPLOAD_ERR_NO_FILE)) {
    $post_error = "A comment, a file, or media links are required."; // Updated message
  } elseif (mb_strlen($comment) > 4000) { // Limit comment length
    $post_error = "Comment is too long (max 4000 characters).";
  } elseif (!$thread_id && empty($posted_channel)) { // New thread needs a channel (should not happen with hidden input)
    $post_error = "Channel not specified for new thread.";
  } elseif (!$thread_id && !in_array($posted_channel, ALLOWED_CHANNELS)) { // Validate channel (should not happen)
    $post_error = "Invalid channel specified.";
  }
  else {
    // Handle file upload (still only handles ONE file input named 'image')
    $upload_result = handle_upload('image');

    if (isset($upload_result['error'])) {
      $post_error = $upload_result['error'];
    } else {
      // Determine the target URL for redirect after successful post

      try {
        $db->beginTransaction();

        $image_filename = $upload_result['filename'] ?? null;
        $image_orig_name = $upload_result['orig_name'] ?? null;
        $image_w = $upload_result['width'] ?? null; // Will be null for non-image types
        $image_h = $upload_result['height'] ?? null; // Will be null for non-image types

        if ($thread_id) { // Posting a Reply
          // Check if thread exists
          $stmt = $db->prepare("SELECT id, channel FROM threads WHERE id = ?"); // Fetch channel here for redirect
          $stmt->execute([$thread_id]);
          $thread_exists = $stmt->fetch();

          if ($thread_exists) {
            // Insert reply
            $stmt = $db->prepare("INSERT INTO replies (thread_id, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$thread_id, $comment, $image_filename, $image_orig_name, $image_w, $image_h]);
            $new_post_id = $db->lastInsertId();

            // Update thread's last reply time
            $stmt = $db->prepare("UPDATE threads SET last_reply_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$thread_id]);

            $db->commit();
            $post_success = "Reply #{$new_post_id} posted successfully.";

            // Redirect back to the page they posted from (board view or thread view)
            $redirect_params = ['channel' => $thread_exists['channel']]; // Use the thread's actual channel for redirect
            if ($viewing_thread_id) {
              // If in thread view, stay in thread view
              $redirect_params['thread'] = $thread_id;
            } else {
              // If in board view, redirect to the thread view to see all replies
              $redirect_params['thread'] = $thread_id;
            }
            $redirect_url = './?' . http_build_query($redirect_params) . '&ts=' . time() . '#post-' . $new_post_id;
            header("Location: " . $redirect_url);
            exit;


          } else {
            $post_error = "Thread not found.";
            $db->rollBack();
          }

        } else { // Posting a New Thread
          // Use the channel derived from the form/current view
          $stmt = $db->prepare("INSERT INTO threads (channel, subject, comment, image, image_orig_name, image_w, image_h) VALUES (?, ?, ?, ?, ?, ?, ?)");
          $stmt->execute([$posted_channel, $subject, $comment, $image_filename, $image_orig_name, $image_w, $image_h]);
          $new_post_id = $db->lastInsertId();

          $db->commit();
          $post_success = "Thread #{$new_post_id} created successfully.";
          // Redirect to the new thread's thread view
          $redirect_url = './?' . http_build_query(['channel' => $posted_channel, 'thread' => $new_post_id]) . '&ts=' . time() . '#post-' . $new_post_id; // Redirect to thread view
          header("Location: " . $redirect_url);
          exit;
        }

      } catch (PDOException $e) {
        $db->rollBack();
        error_log("Database Post Error: " . $e->getMessage());
        $post_error = "Database Error: " . $e->getMessage();
      }
    }
  }
  // If there was an error, the script continues and displays it.
  // If successful, the script exits after the header redirect.
}

// --- Fetch Data for Display (Conditional: Board View or Thread View) ---
$threads = [];
$replies_to_display = []; // Replies to display (preview for board, all for thread view)
$reply_counts = []; // Total reply counts (needed for board view omitted message)
$total_threads = 0; // Needed for board view pagination
$total_pages = 1;   // Needed for board view pagination
$thread_op = null; // Stores the OP data if in thread view
$current_page = 1; // Initialize for board view

try {
  if ($viewing_thread_id) {
    // --- Thread View: Fetch single thread and all replies ---
    $stmt = $db->prepare("SELECT * FROM threads WHERE id = ?");
    $stmt->execute([$viewing_thread_id]);
    $thread_op = $stmt->fetch();

    if ($thread_op) {
      // Set the current channel context to the thread's channel for navigation links etc.
      $current_channel = $thread_op['channel'];

      // Fetch all replies for this thread
      $replies_stmt = $db->prepare("SELECT * FROM replies WHERE thread_id = ? ORDER BY created_at ASC");
      $replies_stmt->execute([$viewing_thread_id]);
      // replies_to_display structure: replies_to_display[thread_id] = [reply1, reply2, ...]
      $replies_to_display[$viewing_thread_id] = $replies_stmt->fetchAll();

      // Total reply count is simply the count of fetched replies
      $reply_counts[$viewing_thread_id] = count($replies_to_display[$viewing_thread_id]);

      // Put the single thread into the threads array for simpler rendering loop below
      // (even though there's only one, simplifies the structure slightly)
      $threads = [$thread_op];

    } else {
      // Thread not found, display error
      $post_error = "Thread with ID " . htmlspecialchars($viewing_thread_id) . " not found in channel /" . htmlspecialchars($current_channel) . "/.";
      // Optionally, redirect to board view after a delay or with a link
    }

  } else {
    // --- Board View: Fetch paginated threads and preview replies ---

    // Determine Current Page for Pagination
    $current_page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT);
    if ($current_page <= 0) {
      $current_page = 1; // Default to page 1
    }

    // Get total thread count for pagination for the current channel
    $count_stmt = $db->prepare("SELECT COUNT(*) FROM threads WHERE channel = ?");
    $count_stmt->execute([$current_channel]);
    $total_threads = $count_stmt->fetchColumn();
    $total_pages = ceil($total_threads / THREADS_PER_PAGE);

    // Ensure current page is not beyond total pages if there are threads
    if ($total_threads > 0 && $current_page > $total_pages) {
      $current_page = $total_pages;
      // Recalculate offset based on corrected page number
      $offset = ($current_page - 1) * THREADS_PER_PAGE;
    } elseif ($total_threads == 0) {
      $current_page = 1; // No threads, stays on page 1 conceptually
      $offset = 0;
    } else {
      // Calculate offset for the valid current page
      $offset = ($current_page - 1) * THREADS_PER_PAGE;
    }


    // Fetch threads for the current channel and page, ordered by latest reply
    $threads_stmt = $db->prepare("SELECT * FROM threads WHERE channel = ? ORDER BY last_reply_at DESC LIMIT ? OFFSET ?");
    $threads_stmt->bindValue(1, $current_channel, PDO::PARAM_STR);
    $threads_stmt->bindValue(2, THREADS_PER_PAGE, PDO::PARAM_INT);
    $threads_stmt->bindValue(3, $offset, PDO::PARAM_INT);
    $threads_stmt->execute();
    $threads = $threads_stmt->fetchAll();

    // Fetch replies for each displayed thread (need counts and first N for preview)
    $threads_on_page_ids = [];
    foreach ($threads as $thread) {
      $threads_on_page_ids[] = $thread['id'];
    }

    if (!empty($threads_on_page_ids)) {
      $placeholders = implode(',', array_fill(0, count($threads_on_page_ids), '?'));

      // Fetch total reply counts for displayed threads
      $count_stmt = $db->prepare("SELECT thread_id, COUNT(*) as count FROM replies WHERE thread_id IN ($placeholders) GROUP BY thread_id");
      $count_stmt->execute($threads_on_page_ids);
      while($row = $count_stmt->fetch()) {
        $reply_counts[$row['thread_id']] = $row['count'];
      }

      // Fetch all replies for the displayed threads to slice for preview
      $all_replies_for_page = [];
      $replies_stmt = $db->prepare("
        SELECT * FROM replies
        WHERE thread_id IN ($placeholders)
        ORDER BY created_at ASC -- Order replies correctly within thread
      ");
      $replies_stmt->execute($threads_on_page_ids);

      // Group all replies by thread_id first
      while ($reply = $replies_stmt->fetch()) {
        if (!isset($all_replies_for_page[$reply['thread_id']])) {
          $all_replies_for_page[$reply['thread_id']] = [];
        }
        $all_replies_for_page[$reply['thread_id']][] = $reply;
      }

      // Now, for display in board view, take only the *first* REPLIES_PREVIEW_COUNT
      foreach ($all_replies_for_page as $tid => $thread_replies) {
        // Take the first N replies for preview
        $replies_to_display[$tid] = array_slice($thread_replies, 0, REPLIES_PREVIEW_COUNT);
      }
    }
  }

} catch (PDOException $e) {
  error_log("Database Fetch Error: " . $e->getMessage());
  die("Database Fetch Error: " . $e->getMessage());
}

?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>/<?php echo $current_channel; ?>/ - HDBoard<?php echo $viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : ''; ?></title>
    <style>
      /* --- Base Styles --- */
      body {
        background-color: #f4f4f4; /* Light grey background */
        color: #333;
        font-family: sans-serif; /* Use sans-serif as a safer default */
        font-size: 10pt;
        margin: 0;
        padding: 0;
      }
      .container {
        max-width: 900px;
        margin: 15px auto;
        padding: 0 15px; /* Add horizontal padding */
      }
      /* Added styles for thread view header */
      .thread-view-header {
        background-color: #c8c8ff;
        border: 1px solid #b7c5d9;
        margin-bottom: 15px;
        padding: 10px;
        text-align: center;
        font-size: 1.2em;
        font-weight: bold;
        color: #0f0c5d;
      }
      .thread-view-header a {
        color: #af0a0f;
        text-decoration: none;
      }
      .thread-view-header a:hover {
        text-decoration: underline;
      }

      header, .post-form, .thread, .reply {
        background-color: #d6daf0; /* 4chan's reply background */
        border: 1px solid #b7c5d9;
        margin-bottom: 10px;
        padding: 5px 10px;
        /* word-wrap: break-word; /* Handle long words - moved to .comment */
        /* overflow-wrap: break-word; /* Handle long words - moved to .comment */
      }
      header {
        background-color: #c8c8ff; /* Slightly different header color */
        text-align: center;
        border-bottom: 1px solid #b7c5d9;
        margin-bottom: 15px;
        padding: 10px;
      }
      header h1 {
        color: #af0a0f; /* Reddish title color */
        margin: 5px 0;
        font-size: 1.8em; /* Slightly larger */
      }
      .channel-nav {
        text-align: center;
        margin-top: 10px;
        padding-top: 5px;
        border-top: 1px dashed #b7c5d9;
        margin-bottom: 15px;
      }
      .channel-nav a {
        margin: 0 5px;
        text-decoration: none;
        color: #0f0c5d; /* Blue link */
        font-weight: bold;
      }
      .channel-nav a:hover {
        color: red;
      }
      .channel-nav a.active {
        text-decoration: underline;
        color: #af0a0f; /* Active channel red */
      }

      hr {
        border: 0;
        border-top: 1px solid #b7c5d9;
        margin: 25px 0; /* More space around hr */
      }
      .post-form {
        padding: 15px;
      }
      .post-form table {
        border-collapse: collapse;
        width: 100%; /* Make table use available width */
      }
      .post-form th, .post-form td {
        padding: 5px; /* Increased padding */
        vertical-align: top;
        text-align: left; /* Align labels left */
      }
      .post-form th {
        width: 100px; /* Fixed width for labels */
        text-align: right;
        font-weight: bold;
        color: #555;
      }
      .post-form td {
        width: auto; /* Let input fields take remaining width */
      }

      .post-form input[type="text"],
      .post-form textarea,
      .post-form select { /* Added select for channels */
        width: calc(100% - 14px); /* Adjust width for padding/border */
        padding: 6px; /* Increased padding */
        border: 1px solid #aaa;
        box-sizing: border-box; /* Include padding and border in element's total width and height */
        font-size: 1em; /* Readable size */
      }
      .post-form textarea {
        resize: vertical; /* Allow vertical resize */
      }

      .post-form input[type="file"] {
        padding: 5px 0; /* Add some vertical padding */
      }

      .post-form input[type="submit"] {
        padding: 5px 15px;
        font-weight: bold;
        cursor: pointer;
      }
      .post-form small {
        color: #666;
      }

      .post-info {
        color: #117743; /* Green name/info color */
        font-weight: bold;
        margin-bottom: 5px; /* Space below info line */
      }
      .post-info .subject {
        color: #0f0c5d; /* Blue subject */
        font-weight: bold;
        margin-right: 5px;
      }
      .post-info .time, .post-info .post-id {
        font-size: 0.9em;
        color: #555;
        font-weight: normal;
        margin-left: 5px;
      }
      .post-info .reply-link {
        font-size: 0.9em;
        color: #555;
        text-decoration: none;
        font-weight: normal;
        margin-left: 5px;
      }
      .post-info .reply-link:hover {
        color: red;
      }
      .post-info .reply-count {
        font-size: 0.9em;
        color: #555;
        font-weight: normal;
        margin-left: 5px;
      }

      .file-info { /* Container for media button and file details */
        font-size: 0.9em;
        color: #666;
        margin-bottom: 5px;
        display: flex;
        align-items: flex-start;
        flex-wrap: wrap; /* Allow button and details to wrap on small screens */
      }
      .file-info .media-toggle { /* Container for the button */
        margin-right: 10px;
        flex-shrink: 0; /* Prevent button from shrinking */
        margin-bottom: 5px; /* Space below button if it wraps */
      }
      .file-info .media-toggle button {
        padding: 5px 10px;
        cursor: pointer;
        font-size: 0.9em;
        /* Simple button styling */
        background-color: #ddd;
        border: 1px solid #ccc;
        border-radius: 3px;
        color: #333;
        /* Override button reset if any */
        line-height: normal;
        text-transform: none;
        white-space: normal;
      }
      .file-info .media-toggle button:hover {
        background-color: #eee;
        border-color: #bbb;
      }
      /* Specific style for YouTube buttons if needed */
      /* .file-info.comment-link-info .media-toggle button[data-media-type="youtube"] { ... } */


      .file-details { /* Container for text like "File: name (size, WxH)" or "Link: url" */
        flex-grow: 1; /* Allow details text to take space */
        margin-top: 7px; /* Align text baseline with button */
      }
      .file-details a { /* Style links within file details */
        color: #666;
        text-decoration: underline;
      }
      .file-details a:hover {
        color: #333;
      }


      .media-container {
        margin-top: 5px;
        margin-bottom: 10px;
        border: 1px dashed #ccc;
        padding: 5px;
        display: none; /* Hidden by default */
        max-width: 100%; /* Prevent overflow */
        box-sizing: border-box;
        overflow: hidden; /* Contain potential floats or large inline elements */
      }
      .media-container img,
      .media-container video,
      .media-container audio,
      .media-container iframe {
        display: block; /* Prevent inline weirdness */
        max-width: 100%; /* Make media responsive */
        height: auto; /* Maintain aspect ratio */
        margin: 0 auto; /* Center media */
      }
      .media-container audio {
        width: 100%; /* Make players fill container width */
      }
      /* --- Aspect Ratio Containers for Video/YouTube (dynamically created by JS) --- */
      .youtube-embed-container, .video-embed-container {
        margin: 10px 0; /* Space around embeds */
        position: relative; /* Needed for aspect ratio trick */
        padding-bottom: 56.25%; /* 16:9 Aspect Ratio (9 / 16 * 100) */
        height: 0;
        overflow: hidden;
        max-width: 100%;
        background: #000; /* Black background while loading */
      }
      .youtube-embed-container iframe,
      .video-embed-container video {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        border: none; /* Remove default iframe/video border */
      }


      .comment {
        margin-top: 10px; /* Space above comment */
        line-height: 1.5; /* Increased line spacing */
        overflow-wrap: break-word; /* Prevent long strings breaking layout */
        word-break: break-word; /* Ensure breaking */
        color: #000000; /* Default comment color */
      }
      /* Styles for text truncation/expansion */
      .comment-truncated {
        /* Styles for the visible, truncated part */
        display: block; /* Ensure it's a block element */
      }
      .comment-full {
        /* Styles for the hidden, full part */
        display: none; /* Hidden by default */
      }
      .show-full-text-btn {
        padding: 2px 5px;
        font-size: 0.8em;
        cursor: pointer;
        margin-left: 5px;
        background-color: #eee;
        border: 1px solid #ccc;
        border-radius: 3px;
        color: #333;
      }
      .show-full-text-btn:hover {
        background-color: #ddd;
      }


      .greentext {
        color: #789922; /* The classic greentext color */
      }
      .reply-mention {
        color: #d00; /* Color for >> reply links */
        text-decoration: underline;
      }
      .reply-mention:hover {
        color: red;
      }


      .thread {
        /* OP Post Styles are largely defined by .post */
        border: 1px solid #b7c5d9; /* OP border */
        background-color: #d6daf0; /* OP background */
        margin-bottom: 10px;
        padding: 5px 10px;
      }

      .reply-container {
        margin-left: 20px; /* Indent replies relative to thread */
        margin-top: 10px; /* Space above reply block */
      }
      .reply {
        background-color: #d6daf0; /* Same background for replies */
        border: 1px solid #b7c5d9; /* Same border */
        margin-top: 5px; /* Space between replies */
        padding: 5px 8px;
        display: block; /* Use block for better flow */
        max-width: calc(100% - 20px); /* Don't let replies get too wide, account for container margin */
        min-width: 200px; /* Give replies a minimum width */
        box-sizing: border-box;
      }
      .reply .post-info {
        margin-bottom: 3px; /* Less space below reply info */
      }


      .omitted-posts {
        font-size: 0.9em;
        color: #707070;
        margin-left: 20px; /* Align with replies */
        margin-top: 5px;
        margin-bottom: 10px; /* Space before replies begin */
      }
      .omitted-posts a {
        color: #707070;
        text-decoration: none;
      }
      .omitted-posts a:hover {
        text-decoration: underline;
      }


      .error {
        color: red;
        font-weight: bold;
        background-color: #fee;
        border: 1px solid red;
        padding: 10px;
        margin-bottom: 10px;
      }
      .success {
        color: green;
        font-weight: bold;
        background-color: #efe;
        border: 1px solid green;
        padding: 10px;
        margin-bottom: 10px;
      }
      /* Add anchor scroll padding */
      :target {
        scroll-margin-top: 20px; /* Adjust as needed to clear header/form */
      }
      .reply-form-container {
        padding: 10px; /* Padding around the form */
        margin-left: 20px; /* Align with replies */
        margin-top: 10px;
        border: 1px dashed #aaa; /* Dashed border */
        background-color: #e4e6ee; /* Slightly lighter than posts */
      }
      .reply-form-container h4 {
        margin: 0 0 10px 0;
        color: #0f0c5d; /* Blue heading */
      }
      .reply-form-container table {
        width: 100%;
      }
      .reply-form-container th {
        width: 80px; /* Smaller width for reply form labels */
      }
      .reply-form-container input[type="text"],
      .reply-form-container textarea,
      .reply-form-container input[type="file"] {
        width: calc(100% - 14px); /* Full width minus padding/border */
      }

      /* --- Pagination Styles --- */
      .pagination {
        text-align: center;
        margin: 20px 0;
        font-size: 1.1em;
      }
      .pagination a, .pagination span {
        display: inline-block;
        padding: 5px 10px;
        margin: 0 2px;
        border: 1px solid #b7c5d9;
        background-color: #d6daf0;
        text-decoration: none;
        color: #0f0c5d;
      }
      .pagination a:hover {
        background-color: #c8c8ff;
      }
      .pagination span.current-page {
        background-color: #af0a0f;
        color: white;
        font-weight: bold;
        border-color: #af0a0f;
      }
      .pagination span.disabled {
        color: #888;
        cursor: not-allowed;
      }


      /* --- Responsive Styles (Mobile First) --- */

      /* Adjustments for screens smaller than 768px (typical tablet portrait) */
      @media (max-width: 767px) {
        body {
          font-size: 11pt; /* Slightly larger font for mobile readability */
        }
        .container {
          padding: 0 10px; /* Reduce horizontal padding */
        }
        header h1 {
          font-size: 1.5em;
        }
        .channel-nav {
          font-size: 0.9em;
        }
        .channel-nav a {
          display: inline-block; /* Allow wrapping */
          margin: 2px 4px;
        }

        .post-form th {
          width: auto; /* Remove fixed width */
          text-align: left; /* Align labels left */
          display: block; /* Stack labels above inputs */
          padding-bottom: 0;
        }
        .post-form td {
          display: block; /* Stack td below th */
          padding-top: 0;
        }
        .post-form input[type="text"],
        .post-form textarea,
        .post-form select,
        .reply-form-container input[type="text"],
        .reply-form-container textarea {
          width: calc(100% - 12px); /* Adjust width for smaller padding/border */
          padding: 5px;
        }
        .post-form input[type="submit"] {
          display: block; /* Make submit button block */
          margin-top: 10px;
        }

        /* Mobile specific file-info layout */
        .file-info {
          flex-direction: column;
          align-items: flex-start; /* Align items left */
        }
        .file-info .media-toggle {
          margin-right: 0;
          margin-bottom: 5px; /* Space below button */
        }
        .file-info .file-details {
          text-align: left;
          font-size: 1em;
          margin-top: 0; /* Remove alignment margin */
        }


        .media-container {
          max-width: 100%; /* Ensure media container respects padding */
        }
        .youtube-embed-container, .video-embed-container {
          padding-bottom: 75%; /* Adjust aspect ratio for smaller screens if needed, or keep 16:9 */
        }


        .reply-container {
          margin-left: 0; /* Remove indentation for replies on small screens */
        }
        .reply, .omitted-posts, .reply-form-container {
          margin-left: 5px; /* Add a small left margin */
          margin-right: 5px; /* Add a small right margin */
          max-width: calc(100% - 10px); /* Adjust max-width */
          min-width: auto; /* Remove min-width */
        }

        .comment {
          margin-top: 5px; /* Less space above comment */
        }
        .post-info {
          font-size: 0.9em; /* Smaller post info font */
        }
        .post-info .time, .post-info .post-id, .post-info .reply-link {
          font-size: 1em; /* Keep relative size */
          margin-left: 3px;
        }

        .pagination {
          font-size: 1em;
        }
        .pagination a, .pagination span {
          padding: 3px 6px; /* Smaller pagination buttons */
        }

        .thread-view-header {
          font-size: 1em;
        }

        .desktop-hidden {
          display: block; /* Ensure HR is visible on mobile */
        }


      }

      /* --- Desktop Styles (Min-width: 768px) --- */
      @media (min-width: 768px) {
        .container {
          padding: 0 15px;
        }
        .post-form th {
          width: 100px; /* Restore fixed width */
          text-align: right;
          display: table-cell; /* Restore table cell display */
        }
        .post-form td {
          display: table-cell; /* Restore table cell display */
        }
        /* Desktop specific file-info layout */
        .file-info {
          flex-direction: row;
          align-items: flex-start;
        }
        .file-info .media-toggle {
          margin-right: 10px;
          margin-bottom: 0; /* Remove bottom margin */
        }
        .file-info .file-details {
          text-align: left;
          margin-top: 7px; /* Restore alignment margin */
        }


        .reply-container {
          margin-left: 20px; /* Restore indentation */
        }
        .reply, .omitted-posts, .reply-form-container {
          margin-left: 20px;
          margin-right: 0;
          max-width: calc(100% - 20px);
        }
        .reply-form-container th {
          width: 80px; /* Restore width */
        }

        /* --- Desktop Column Layout (Board View Only) --- */
        .board-layout {
          display: flex;
          gap: 20px; /* Space between columns */
          align-items: flex-start; /* Align columns to the top */
        }

        .post-form-col {
          flex: 0 0 300px; /* Fixed width for form column */
          max-width: 300px; /* Ensure it doesn't exceed */
          /* Adjust padding/margin if needed, currently inherits from .post-form */
          position: sticky; /* Make form sticky */
          top: 15px; /* Stick 15px from the top */
          /* Needs a parent with position: relative on body or container */
        }


        .threads-col {
          flex-grow: 1; /* Take up remaining space */
          /* Adjust padding/margin if needed */
        }

        /* Adjust elements within columns that might need it */
        .board-layout .post-form {
          margin-bottom: 0; /* Remove bottom margin when in column layout */
        }
        .board-layout hr {
          display: none; /* Hide HR separators between form and threads in column view */
        }
        .desktop-hidden {
          display: none; /* Hide HR on desktop column layout */
        }


      }


    </style>
    <script>
      // Define lists of media types handled by the dynamic loader
      // These should align with get_render_media_type in PHP
      const IMAGE_TYPES = ['image'];
      const VIDEO_TYPES = ['video']; // PHP determines these now
      const AUDIO_TYPES = ['audio'];       // PHP determines these now
      const YOUTUBE_TYPE = 'youtube'; // Single type for YouTube


      // Simple toggle for reply form - basic JS enhancement
      function toggleReplyForm(threadId) {
        var form = document.getElementById('reply-form-' + threadId);
        var link = document.getElementById('reply-link-' + threadId);
        if (form && link) {
          var isHidden = (form.style.display === 'none' || form.style.display === '');
          form.style.display = isHidden ? 'block' : 'none';
          // Optional: change link text
          // link.textContent = isHidden ? '[Hide Reply Form]' : '[Reply]';

          // Scroll to the form if it was shown
          if (isHidden) {
            form.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }
      }

      // Toggle media visibility and dynamically load media
      function toggleMedia(button, mediaId) {
        const mediaContainer = document.getElementById('media-container-' + mediaId);
        if (!mediaContainer) return; // Safety check

        const isHidden = (mediaContainer.style.display === 'none' || mediaContainer.style.display === '');
        const mediaUrl = button.dataset.mediaUrl;
        const mediaType = button.dataset.mediaType; // Type determined by PHP (image, video, audio, youtube)

        if (isHidden) {
          // Show container
          mediaContainer.style.display = 'block';
          button.textContent = 'Hide Media'; // Change button text

          // Load media if not already loaded (container is empty)
          // Also check if loaded URL matches current URL (handle rare cases?)
          if (mediaContainer.innerHTML.trim() === '' || mediaContainer.dataset.loadedUrl !== mediaUrl) {
            // Clear previous content if URL changed (shouldn't happen with unique IDs, but defensive)
            mediaContainer.innerHTML = '';
            mediaContainer.dataset.loadedUrl = mediaUrl; // Mark URL as loaded

            let mediaElementHTML = '';

            if (IMAGE_TYPES.includes(mediaType)) {
              mediaElementHTML = `<img src="${mediaUrl}" alt="Media Image">`; // Basic img tag, responsive CSS handles fluid
            } else if (VIDEO_TYPES.includes(mediaType)) {
              // Use aspect ratio container for responsiveness
              mediaElementHTML = `<div class="video-embed-container"><video src="${mediaUrl}" controls playsinline preload="none"></video></div>`; // Added playsinline, preload
            } else if (AUDIO_TYPES.includes(mediaType)) {
              mediaElementHTML = `<audio src="${mediaUrl}" controls preload="none"></audio>`; // Added preload
            } else if (mediaType === YOUTUBE_TYPE) {
              // Extract video ID from various YouTube URLs (JS parsing logic from user reference)
              let videoId = null;
              // Updated regex to match user's potential sources including shorts and mobile
              const youtubeRegexMatch = mediaUrl.match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|v\/|shorts\/)|m\.youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/);
              if (youtubeRegexMatch && youtubeRegexMatch[1]) {
                videoId = youtubeRegexMatch[1];
              }

              if (videoId) {
                // Use standard YouTube embed path
                const embedUrl = `https://www.youtube.com/embed/${videoId}`; // Correct embed URL format, use https
                // Use the standard youtube-embed-container for iframes
                mediaElementHTML = `<div class="youtube-embed-container"><iframe src="${embedUrl}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen loading="lazy"></iframe></div>`; // Updated allow attribute
              } else {
                mediaElementHTML = 'Failed to embed YouTube video (Invalid URL).';
              }
            } else {
              mediaElementHTML = 'Unsupported media type: ' + mediaType;
            }

            mediaContainer.innerHTML = mediaElementHTML;

            // For video/audio, try to load media data after adding to DOM for correct playback
            mediaContainer.querySelectorAll('video, audio').forEach(mediaElement => {
              if (mediaElement.preload === 'none') { // Only if not preloaded
                mediaElement.load(); // Request resource loading
              }
            });


          } // else: media already loaded, just toggled display
        } else {
          // Hide container
          mediaContainer.style.display = 'none';
          button.textContent = 'View Media'; // Change button text

          // Optional: Stop media playback when hidden
          mediaContainer.querySelectorAll('video, audio, iframe').forEach(mediaElement => {
            // For video/audio
            if (typeof mediaElement.pause === 'function' && !mediaElement.paused) {
              mediaElement.pause();
            }
            // For iframes (complex, may not always work)
            // Sending a postMessage to the iframe to pause video (standard YouTube API approach)
            if (mediaElement.tagName === 'IFRAME' && mediaElement.contentWindow) {
              try {
                // Ensure the iframe's source is a YouTube embed URL for this API to work
                if (mediaElement.src.includes('https://www.youtube.com/embed/')) {
                  mediaElement.contentWindow.postMessage('{"event":"command","func":"pauseVideo","args":""}', '*');
                }
              } catch (e) {
                // console.error("Error sending pause command to iframe:", e); // Log if needed
              }
            }
          });
        }
      }

      // Toggle full text visibility
      function toggleFullText(button, fullTextId) {
        const truncatedDiv = button.closest('.comment-truncated');
        const fullDiv = document.getElementById(fullTextId);

        if (truncatedDiv && fullDiv) {
          truncatedDiv.style.display = 'none';
          fullDiv.style.display = 'block';
          // Button text could be changed, but simpler to just show full text
          // button.textContent = 'Hide Full Text'; // If adding hide functionality
        }
      }


      // DOM ready
      document.addEventListener('DOMContentLoaded', function() {
        // Attach click listeners to media toggle buttons
        document.querySelectorAll('.show-media-btn').forEach(function(button) {
          const mediaId = button.dataset.mediaId; // Use dataset for data- attributes
          if (mediaId) {
            button.addEventListener('click', function() {
              toggleMedia(this, mediaId); // Pass the button element and the mediaId
            });
          }
        });

        // Attach click listeners to text expansion buttons
        document.querySelectorAll('.show-full-text-btn').forEach(function(button) {
          const fullTextId = button.dataset.targetId;
          if (fullTextId) {
            button.addEventListener('click', function() {
              toggleFullText(this, fullTextId);
            });
          }
        });


        // Add hover effect for reply mentions
        document.querySelectorAll('.reply-mention').forEach(function(link) {
          const targetId = link.getAttribute('href').substring(1); // Get id from #anchor
          const targetPost = document.getElementById(targetId);

          if (targetPost) {
            link.addEventListener('mouseover', function() {
              targetPost.style.backgroundColor = '#e0e9ff'; // Highlight color
              targetPost.style.border = '1px solid #a0b0ff'; // Highlight border
            });
            link.addEventListener('mouseout', function() {
              // Reset to original styles (might need to store them if complex)
              if (targetPost.classList.contains('op') || targetPost.classList.contains('reply')) {
                targetPost.style.backgroundColor = '#d6daf0'; // Assuming both use this
                targetPost.style.border = '1px solid #b7c5d9';
              } else {
                targetPost.style.backgroundColor = '';
                targetPost.style.border = '';
              }
            });
            // Optional: smooth scroll when clicking mention links (already handled by default anchor behavior unless eventDefault is used)
          }
        });
      });
    </script>
  </head>
  <body>
    <div class="container">
      <header>
        <h1>/<?php echo htmlspecialchars($current_channel); ?>/ - HDBoard<?php echo $viewing_thread_id ? ' - Thread No.' . htmlspecialchars($viewing_thread_id) : ''; ?></h1>
        <div class="channel-nav">
          <?php foreach (ALLOWED_CHANNELS as $channel): ?>
            <a href="./?channel=<?php echo urlencode($channel); ?>" class="<?php echo ($channel === $current_channel) ? 'active' : ''; ?>">/<?php echo htmlspecialchars($channel); ?>/</a>
          <?php endforeach; ?>
        </div>
      </header>

      <?php if ($post_error): ?>
        <p class="error"><?php echo htmlspecialchars($post_error); ?></p>
      <?php endif; ?>
      <?php if ($post_success): ?>
        <p class="success"><?php echo htmlspecialchars($post_success); ?></p>
      <?php endif; ?>
      <?php // Success messages are usually not seen due to redirect ?>


      <?php if ($viewing_thread_id && $thread_op): // --- Thread View --- ?>

        <div class="thread-view-header">
          <a href="./?channel=<?php echo urlencode($current_channel); ?>"><< Back to /<?php echo htmlspecialchars($current_channel); ?>/</a>
        </div>

        <?php // Reply form is always available in thread view ?>
        <div class="post-form" id="post-form">
          <h4>Reply to Thread No.<?php echo $viewing_thread_id; ?></h4>
          <form action="./" method="post" enctype="multipart/form-data"> <!-- Action changed to ./ -->
            <input type="hidden" name="thread_id" value="<?php echo $viewing_thread_id; ?>">
            <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel); ?>"> <!-- Submit current channel -->
            <table>
              <tr>
                <th><label for="reply_comment">Comment</label></th> <!-- Simplified ID -->
                <td><textarea name="comment" id="reply_comment" rows="4" cols="45" required></textarea></td>
              </tr>
              <tr>
                <th><label for="reply_image">File</label></th>
                <td><input type="file" name="image" id="reply_image" accept="<?php echo implode(',', array_map(function($ext) {
                    if (in_array($ext, VIDEO_EXTENSIONS)) return 'video/*';
                    if (in_array($ext, AUDIO_EXTENSIONS)) return 'audio/*';
                    return 'image/*';
                    }, ALLOWED_EXTENSIONS)); ?>"></td>
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
        // Display the single thread (OP)
        $thread = $thread_op; // Use the fetched thread_op data
        $thread_id = $thread['id'];
        $post_element_id = 'post-' . $thread_id;

        $post_media_buttons_html = ''; // Initialize media buttons/containers HTML for this post
        $cleaned_comment_content_raw = $thread['comment']; // Get original comment content

        // --- Handle Uploaded File for OP ---
        if ($thread['image']) {
          $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($thread['image']);
          $orig_name = htmlspecialchars($thread['image_orig_name'] ?? $thread['image']);
          $img_w = $thread['image_w'] ?? '?';
          $img_h = $thread['image_h'] ?? '?';
          $file_size = @filesize(UPLOADS_DIR . '/' . $thread['image']);
          $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
          $uploaded_media_type = get_render_media_type($thread['image']); // Use the general helper function

          $post_media_buttons_html .= "
            <div class='file-info uploaded-file-info'>
              <div class='media-toggle'>
                <button class='show-media-btn'
                    data-media-id='{$post_element_id}-uploaded'
                    data-media-url='{$uploaded_media_url}'
                    data-media-type='{$uploaded_media_type}'>View Uploaded File</button>
              </div>
              <span class='file-details'>
                File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}, {$img_w}x{$img_h})
              </span>
            </div>
            <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'>
              " . "<!-- Uploaded media dynamically loaded here -->" . "
            </div>";
        }

        // --- Process Media Links (including YouTube) in Comment for OP ---
        $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
        $cleaned_comment_content_raw = $link_media_result['cleaned_text']; // Get comment text with links removed
        $post_media_buttons_html .= $link_media_result['media_html']; // Append media link buttons/containers

        // --- Format the cleaned comment content ---
        $formatted_comment = format_comment($cleaned_comment_content_raw);

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
              <?php // Reply link not needed for OP in thread view ?>
              <?php // Reply count not shown in thread view header per post ?>
            </p>
            <?php echo $post_media_buttons_html; // Display combined media buttons/containers ?>
            <div class="comment">
              <?php
              // In thread view, comments are NOT truncated
              echo $formatted_comment;
              ?>
            </div>
          </div>

          <div class="reply-container">
            <?php // In thread view, we show ALL replies, no omitted message ?>

            <?php
            // replies_to_display[$thread_id] contains ALL replies in thread view
            $all_thread_replies = $replies_to_display[$thread_id] ?? [];
            foreach ($all_thread_replies as $reply):
              $reply_id = $reply['id'];
              $post_element_id = 'post-' . $reply_id; // Unique ID for this reply

              $reply_media_buttons_html = ''; // Initialize media buttons/containers HTML for this reply
              $cleaned_comment_content_raw = $reply['comment'];

              // --- Handle Uploaded File for Reply ---
              if ($reply['image']) {
                $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($reply['image']);
                $orig_name = htmlspecialchars($reply['image_orig_name'] ?? $reply['image']);
                $img_w = $reply['image_w'] ?? '?'; // These might be null for non-images
                $img_h = $reply['image_h'] ?? '?'; // These might be null for non-image
                $file_size = @filesize(UPLOADS_DIR . '/' . $reply['image']);
                $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                $uploaded_media_type = get_render_media_type($reply['image']); // Use general helper

                $reply_media_buttons_html .= "
                  <div class='file-info uploaded-file-info'>
                    <div class='media-toggle'>
                      <button class='show-media-btn'
                          data-media-id='{$post_element_id}-uploaded'
                          data-media-url='{$uploaded_media_url}'
                          data-media-type='{$uploaded_media_type}'>View Uploaded File</button>
                    </div>
                    <span class='file-details'>
                      File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}, {$img_w}x{$img_h})
                    </span>
                  </div>
                  <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'>
                    " . "<!-- Uploaded media dynamically loaded here -->" . "
                  </div>";
              }

              // --- Process Media Links (including YouTube) in Comment for Reply ---
              $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
              $cleaned_comment_content_raw = $link_media_result['cleaned_text']; // Get comment text with links removed
              $reply_media_buttons_html .= $link_media_result['media_html']; // Append media link buttons/containers

              // --- Format the cleaned comment content ---
              $formatted_comment = format_comment($cleaned_comment_content_raw);

            ?>
              <div class="reply" id="post-<?php echo $reply_id; ?>">
                <p class="post-info">
                  <span class="name">Anonymous</span>
                  <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                  <span class="post-id">No.<?php echo $reply_id; ?></span>
                  <a href="#post-<?php echo $reply_id; ?>" class="reply-link">▶</a>
                </p>
                <?php echo $reply_media_buttons_html; // Display combined media buttons/containers ?>
                <div class="comment">
                  <?php
                  // In thread view, comments are NOT truncated
                  echo $formatted_comment;
                  ?>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div><hr>


      <?php elseif ($total_threads == 0): // --- Board View, No Threads --- ?>

        <div class="post-form-col"> <!-- Wrap form even if no threads -->
          <div class="post-form" id="post-form">
            <h2>Post a new thread in /<?php echo htmlspecialchars($current_channel); ?>/</h2>
            <form action="./" method="post" enctype="multipart/form-data"> <!-- Action changed to ./ -->
              <input type="hidden" name="form_type" value="new_thread">
              <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel); ?>"> <!-- Submit current channel -->
              <table>
                <tr>
                  <th><label for="subject">Subject</label></th>
                  <td><input type="text" name="subject" id="subject" size="30"></td>
                </tr>
                <tr>
                  <th><label for="comment">Comment</label></th>
                  <td><textarea name="comment" id="comment" rows="5" cols="50" required></textarea></td>
                </tr>
                <tr>
                  <th><label for="image">File</label></th> <!-- Changed label from Image to File -->
                  <td><input type="file" name="image" id="image" accept="<?php echo implode(',', array_map(function($ext) {
                    if (in_array($ext, VIDEO_EXTENSIONS)) return 'video/*';
                    if (in_array($ext, AUDIO_EXTENSIONS)) return 'audio/*';
                    return 'image/*';
                    }, ALLOWED_EXTENSIONS)); ?>"></td> <!-- Updated accept attribute -->
                </tr>
                <tr>
                  <th></th>
                  <td><input type="submit" value="Submit"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td>
                </tr>
              </table>
            </form>
          </div>
          <hr class="desktop-hidden"> <!-- Hide this HR on desktop column layout -->
        </div>

        <p style="text-align: center; color: #777;">No threads in /<?php echo htmlspecialchars($current_channel); ?>/ yet. Why not start one?</p>


      <?php else: // --- Board View, With Threads (Apply Column Layout) --- ?>

        <div class="board-layout">
          <div class="post-form-col">
            <div class="post-form" id="post-form">
              <h2>Post a new thread in /<?php echo htmlspecialchars($current_channel); ?>/</h2>
              <form action="./" method="post" enctype="multipart/form-data"> <!-- Action changed to ./ -->
                <input type="hidden" name="form_type" value="new_thread">
                <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel); ?>"> <!-- Submit current channel -->
                <?php // Keep current page hidden input if we want to return to the same page after new thread post (less common) ?>
                <?php // <input type="hidden" name="current_page" value="<?php echo $current_page; "> ?>
                <table>
                  <tr>
                    <th><label for="subject">Subject</label></th>
                    <td><input type="text" name="subject" id="subject" size="30"></td>
                  </tr>
                  <tr>
                    <th><label for="comment">Comment</label></th>
                    <td><textarea name="comment" id="comment" rows="5" cols="50" required></textarea></td>
                  </tr>
                  <tr>
                    <th><label for="image">File</label></th> <!-- Changed label from Image to File -->
                    <td><input type="file" name="image" id="image" accept="<?php echo implode(',', array_map(function($ext) {
                        if (in_array($ext, VIDEO_EXTENSIONS)) return 'video/*';
                        if (in_array($ext, AUDIO_EXTENSIONS)) return 'audio/*';
                        return 'image/*';
                        }, ALLOWED_EXTENSIONS)); ?>"></td> <!-- Updated accept attribute -->
                  </tr>
                  <tr>
                    <th></th>
                    <td><input type="submit" value="Submit"> <small>(Max: <?php echo MAX_FILE_SIZE / 1024 / 1024; ?> MB)</small></td>
                  </tr>
                </table>
              </form>
            </div>
            <hr class="desktop-hidden"> <!-- Hide this HR on desktop column layout -->
          </div>

          <div class="threads-col">

            <?php // Pagination (Top) ?>
            <div class="pagination">
              <?php if ($current_page > 1): ?>
                <a href="./?channel=<?php echo urlencode($current_channel); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a>
              <?php else: ?>
                <span class="disabled"><< Prev</span>
              <?php endif; ?>

              <?php // Simple page number display ?>
              <span>Page <span class="current-page"><?php echo $current_page; ?></span> of <?php echo $total_pages; ?></span>

              <?php if ($current_page < $total_pages): ?>
                <a href="./?channel=<?php echo urlencode($current_channel); ?>&page=<?php echo $current_page + 1; ?>">Next >></a>
              <?php else: ?>
                <span class="disabled">Next >></span>
              <?php endif; ?>
            </div>
            <hr>

            <?php foreach ($threads as $thread):
              $thread_id = $thread['id'];
              $post_element_id = 'post-' . $thread_id; // Unique ID for this thread

              // Use the pre-sliced replies for preview
              $thread_replies_preview = $replies_to_display[$thread_id] ?? [];
              // Total count comes from the reply_counts array
              $total_reply_count = $reply_counts[$thread_id] ?? 0;
              // Calculate omitted count based on the total count and the preview size
              $omitted_count = $total_reply_count - count($thread_replies_preview);

              $thread_media_buttons_html = ''; // Initialize media buttons/containers HTML for this thread
              $cleaned_comment_content_raw = $thread['comment']; // Get original comment content

              // --- Handle Uploaded File for Thread ---
              if ($thread['image']) {
                $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($thread['image']);
                $orig_name = htmlspecialchars($thread['image_orig_name'] ?? $thread['image']);
                $img_w = $thread['image_w'] ?? '?';
                $img_h = $thread['image_h'] ?? '?';
                $file_size = @filesize(UPLOADS_DIR . '/' . $thread['image']);
                $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                $uploaded_media_type = get_render_media_type($thread['image']); // Use general helper

                $thread_media_buttons_html .= "
                  <div class='file-info uploaded-file-info'>
                    <div class='media-toggle'>
                      <button class='show-media-btn'
                          data-media-id='{$post_element_id}-uploaded'
                          data-media-url='{$uploaded_media_url}'
                          data-media-type='{$uploaded_media_type}'>View Uploaded File</button>
                    </div>
                    <span class='file-details'>
                      File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}, {$img_w}x{$img_h})
                    </span>
                  </div>
                  <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'>
                    " . "<!-- Uploaded media dynamically loaded here -->" . "
                  </div>";
              }

              // --- Process Media Links (including YouTube) in Comment for Thread ---
              $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
              $cleaned_comment_content_raw = $link_media_result['cleaned_text']; // Get comment text with links removed
              $thread_media_buttons_html .= $link_media_result['media_html']; // Append media link buttons/containers

              // --- Format the cleaned comment content ---
              $formatted_comment = format_comment($cleaned_comment_content_raw);

              // --- Handle text truncation for board view ---
              $display_comment_html = '';
              $full_comment_html = $formatted_comment; // Full formatted text

              if (mb_strlen($cleaned_comment_content_raw) > COMMENT_PREVIEW_LENGTH) {
                // Truncate the *cleaned, raw* comment content
                $truncated_raw_comment = mb_substr($cleaned_comment_content_raw, 0, COMMENT_PREVIEW_LENGTH);
                // Format the truncated part
                $truncated_formatted_comment = format_comment($truncated_raw_comment);

                // Display truncated part + button
                $display_comment_html = "
                  <div class='comment-truncated'>
                    {$truncated_formatted_comment}...
                    <button class='show-full-text-btn' data-target-id='full-comment-{$post_element_id}'>View Full Text</button>
                  </div>
                  <div id='full-comment-{$post_element_id}' class='comment-full'>
                    {$full_comment_html}
                  </div>";
              } else {
                // Display full formatted text if not long enough to truncate
                $display_comment_html = $full_comment_html;
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
                    <span class="reply-link">[<a href="#reply-form-<?php echo $thread_id; ?>" id="reply-link-<?php echo $thread_id; ?>" onclick="toggleReplyForm(<?php echo $thread_id; ?>); return false;">Reply</a>]</span>
                    <?php if ($total_reply_count > 0): ?>
                      <span class="reply-count">(<?php echo $total_reply_count; ?> replies)</span>
                    <?php endif; ?>
                  </p>
                  <?php echo $thread_media_buttons_html; // Display combined media buttons/containers ?>
                  <div class="comment">
                    <?php echo $display_comment_html; // Display truncated or full comment HTML ?>
                  </div>
                </div>

                <div class="reply-form-container" id="reply-form-<?php echo $thread_id; ?>" style="display: none;">
                  <h4>Reply to Thread No.<?php echo $thread_id; ?></h4>
                  <form action="./" method="post" enctype="multipart/form-data"> <!-- Action changed to ./ -->
                    <input type="hidden" name="thread_id" value="<?php echo $thread_id; ?>">
                    <input type="hidden" name="channel" value="<?php echo htmlspecialchars($current_channel); ?>"> <!-- Submit current channel -->
                    <?php // Keep current page hidden input if we want to return to the same page after reply ?>
                    <?php // <input type="hidden" name="current_page" value="<?php echo $current_page; "> ?>
                    <table>
                      <tr>
                        <th><label for="reply_comment_<?php echo $thread_id; ?>">Comment</label></th>
                        <td><textarea name="comment" id="reply_comment_<?php echo $thread_id; ?>" rows="4" cols="45" required></textarea></td>
                      </tr>
                      <tr>
                        <th><label for="reply_image_<?php echo $thread_id; ?>">File</label></th>
                        <td><input type="file" name="image" id="reply_image_<?php echo $thread_id; ?>" accept="<?php echo implode(',', array_map(function($ext) {
                            if (in_array($ext, VIDEO_EXTENSIONS)) return 'video/*';
                            if (in_array($ext, AUDIO_EXTENSIONS)) return 'audio/*';
                            return 'image/*';
                            }, ALLOWED_EXTENSIONS)); ?>"></td>
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
                      [<a href="./?channel=<?php echo urlencode($current_channel); ?>&thread=<?php echo $thread_id; ?>">View all <?php echo $total_reply_count; ?> replies</a>]
                    </p>
                  <?php endif; ?>

                  <?php foreach ($replies_to_display[$thread_id] ?? [] as $reply): // Use replies_to_display for preview ?>

                    <?php
                      $reply_id = $reply['id'];
                      $post_element_id = 'post-' . $reply_id; // Unique ID for this reply

                      $reply_media_buttons_html = ''; // Initialize media buttons/containers HTML for this reply
                      $cleaned_comment_content_raw = $reply['comment'];

                      // --- Handle Uploaded File for Reply ---
                      if ($reply['image']) {
                        $uploaded_media_url = UPLOADS_URL_PATH . '/' . htmlspecialchars($reply['image']);
                        $orig_name = htmlspecialchars($reply['image_orig_name'] ?? $reply['image']);
                        $img_w = $reply['image_w'] ?? '?'; // These might be null for non-images
                        $img_h = $reply['image_h'] ?? '?'; // These might be null for non-image
                        $file_size = @filesize(UPLOADS_DIR . '/' . $reply['image']);
                        $file_size_kb = $file_size ? round($file_size / 1024) . ' KB' : '? KB';
                        $uploaded_media_type = get_render_media_type($reply['image']); // Use general helper

                        $reply_media_buttons_html .= "
                          <div class='file-info uploaded-file-info'>
                            <div class='media-toggle'>
                              <button class='show-media-btn'
                                  data-media-id='{$post_element_id}-uploaded'
                                  data-media-url='{$uploaded_media_url}'
                                  data-media-type='{$uploaded_media_type}'>View Uploaded File</button>
                            </div>
                            <span class='file-details'>
                              File: <a href='{$uploaded_media_url}' target='_blank' rel='noopener noreferrer'>{$orig_name}</a> ({$file_size_kb}, {$img_w}x{$img_h})
                            </span>
                          </div>
                          <div id='media-container-{$post_element_id}-uploaded' class='media-container' style='display:none;'>
                            " . "<!-- Uploaded media dynamically loaded here -->" . "
                          </div>";
                      }

                      // --- Process Media Links (including YouTube) in Comment for Reply ---
                      $link_media_result = process_comment_media_links($cleaned_comment_content_raw, $post_element_id);
                      $cleaned_comment_content_raw = $link_media_result['cleaned_text']; // Get comment text with links removed
                      $reply_media_buttons_html .= $link_media_result['media_html']; // Append media link buttons/containers

                      // --- Format the cleaned comment content ---
                      $formatted_comment = format_comment($cleaned_comment_content_raw);

                      // --- Handle text truncation for board view replies ---
                      $display_comment_html = '';
                      $full_comment_html = $formatted_comment; // Full formatted text

                      // Only truncate in board view (this foreach loop is inside board view conditional)
                      if (mb_strlen($cleaned_comment_content_raw) > COMMENT_PREVIEW_LENGTH) {
                        // Truncate the *cleaned, raw* comment content
                        $truncated_raw_comment = mb_substr($cleaned_comment_content_raw, 0, COMMENT_PREVIEW_LENGTH);
                        // Format the truncated part
                        $truncated_formatted_comment = format_comment($truncated_raw_comment);

                        // Display truncated part + button
                        $display_comment_html = "
                          <div class='comment-truncated'>
                            {$truncated_formatted_comment}...
                            <button class='show-full-text-btn' data-target-id='full-comment-{$post_element_id}'>View Full Text</button>
                          </div>
                          <div id='full-comment-{$post_element_id}' class='comment-full'>
                            {$full_comment_html}
                          </div>";
                      } else {
                        // Display full formatted text if not long enough to truncate
                        $display_comment_html = $full_comment_html;
                      }

                    ?>
                    <div class="reply" id="post-<?php echo $reply_id; ?>">
                      <p class="post-info">
                        <span class="name">Anonymous</span>
                        <span class="time"><?php echo date('Y/m/d(D) H:i:s', strtotime($reply['created_at'])); ?></span>
                        <span class="post-id">No.<?php echo $reply_id; ?></span>
                        <a href="#post-<?php echo $reply_id; ?>" class="reply-link">▶</a>
                      </p>
                      <?php echo $reply_media_buttons_html; // Display combined media buttons/containers ?>
                      <div class="comment">
                        <?php echo $display_comment_html; // Display truncated or full comment HTML ?>
                      </div>
                    </div>
                  <?php endforeach; ?>
                </div>
              </div><hr>
            <?php endforeach; ?>

            <?php // Pagination (Bottom) ?>
            <div class="pagination">
              <?php if ($current_page > 1): ?>
                <a href="./?channel=<?php echo urlencode($current_channel); ?>&page=<?php echo $current_page - 1; ?>"><< Prev</a>
              <?php else: ?>
                <span class="disabled"><< Prev</span>
              <?php endif; ?>

              <span>Page <span class="current-page"><?php echo $current_page; ?></span> of <?php echo $total_pages; ?></span>

              <?php if ($current_page < $total_pages): ?>
                <a href="./?channel=<?php echo urlencode($current_channel); ?>&page=<?php echo $current_page + 1; ?>">Next >></a>
              <?php else: ?>
                <span class="disabled">Next >></span>
              <?php endif; ?>
            </div>

          </div><?php // End .threads-col ?>
        </div><?php // End .board-layout ?>

      <?php endif; // End of Board View With Threads conditional ?>


    </div>
  </body>
</html>