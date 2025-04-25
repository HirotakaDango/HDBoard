<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
      /* Define CSS variables for the dark theme */
      :root {
        --bg-color: #1a1a1a;
        --text-color: #e0e0e0;
        --border-color: #444;
        --post-bg: #282828;
        --header-bg: #333;
        --link-color: #7aa2f7;
        --link-hover: #c0caf5;
        --accent-red: #f7768e;
        --accent-green: #9ece6a;
        --accent-blue: #4f6dac;
        --greentext-color: #9ece6a;
        --reply-mention-color: #f7768e;
        --form-bg: #303030;
        --input-bg: #404040;
        --input-text: #e0e0e0;
        --input-border: #555;
        --button-bg: #555;
        --button-hover-bg: #666;
        --button-text: #e0e0e0;
        --warning-bg: #5c2424;
        --warning-border: #a04040;
        --warning-text: #f7768e;
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
        --summary-bg: var(--button-bg);
        --summary-hover-bg: var(--button-hover-bg);
      }

      /* Basic body styling - Centered and Full Height */
      body {
        font-family: 'Courier New', Courier, monospace; /* Monospace font */
        background-color: var(--bg-color); /* Use background variable */
        color: var(--text-color); /* Use text color variable */
        margin: 0; /* Remove default body margin */
        line-height: 1.6; /* Improve line spacing */

        /* Flexbox properties for centering */
        display: flex;
        justify-content: center; /* Center horizontally */
        align-items: center; /* Center vertically */

        min-height: 100vh; /* Ensure body takes at least full viewport height */
        text-align: center; /* Center text within the container */
      }

      /* Container for the main content */
      .container {
        border: 1px solid var(--border-color); /* Use border color variable */
        padding: 15px; /* Add padding */
        max-width: 600px; /* Limit width - content will not exceed this */
        /* Removed width: 90%; to prevent it from fitting screen width */
        margin: auto 1.5em; /* Auto margins help center block elements horizontally */
        background-color: var(--post-bg); /* Use post background variable */
        border-radius: 5px; /* Add slight rounding */
        box-sizing: border-box; /* Include padding and border in element's total width and height */
      }

      /* Styling for the main heading */
      h1 {
        font-size: 1.5em; /* Slightly larger font */
        margin-top: 0; /* Remove top margin */
        margin-bottom: 10px; /* Space below heading */
        color: var(--accent-red); /* Use accent red for heading */
      }

      /* Styling for the paragraph text (often green text) */
      p {
        color: var(--greentext-color); /* Use green text color variable */
        margin-bottom: 15px; /* Space below paragraph */
      }

      /* Styling for the "Go Home" button (anchor tag) */
      .go-home-button {
        display: inline-block; /* Make it behave like a block but inline */
        padding: 5px 10px; /* Padding inside the button */
        background-color: var(--button-bg); /* Use button background variable */
        color: var(--button-text); /* Use button text color variable */
        text-decoration: none; /* Remove underline from link */
        border: 1px solid var(--border-color); /* Use border color for button border */
        font-size: 1em; /* Font size */
        cursor: pointer; /* Indicate it's clickable */
        border-radius: 3px; /* Add slight rounding to button */
        transition: background-color 0.3s ease; /* Smooth transition */
      }

      /* Hover effect for the button */
      .go-home-button:hover {
        background-color: var(--button-hover-bg); /* Use button hover background variable */
      }
    </style>
  </head>
  <body>

    <div class="container">
      <h1>Access Denied</h1>
      <p>>You do not have permission to access this database.</p> <a href="./" class="go-home-button">[ Go Back ]</a> </div>

  </body>
</html>
