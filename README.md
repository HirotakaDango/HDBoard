# HDBoard

<p align="center">
  <img src="https://github.com/user-attachments/assets/86b8fd56-cc5f-46a7-bc15-ba88dd096f8f" alt="HDBoard Logo">
</p>

**HDBoard** is a lightweight and customizable PHP-based message board system inspired by 4chan, designed to be simple, fast, and easy to deploy. Ideal for small communities, personal projects, or internal team boards, HDBoard runs as a single PHP file and uses SQLite for storage.

---

## Features

- **Single File**: Just one `index.php` file to deploy.
- **Easy Installation**: No dependencies besides PHP 7+; SQLite DB is created automatically.
- **Multiple Boards**: Supports dozens of boards/channels, grouped by category.
- **User Accounts & Legacy Posting**: Register/login or post as a legacy/anonymous user.
- **Media Uploads**: Supports image, video, and audio attachments (with previews).
- **BBCode Formatting**: Rich text support with BBCode (bold, italics, spoiler, code, quote, etc).
- **Role-Based Moderation**: Admin, moderator, janitor, and user roles; users can be banned/unbanned.
- **Post Management**: Edit and delete your own posts; moderators can manage others.
- **Security**: CSRF protection, session security, basic input validation.
- **Responsive UI**: Minimal, mobile-friendly interface with dark mode and quick navigation.
- **Customizable**: Change board titles, categories, and appearance by editing the file.

---

## Getting Started

### Requirements

- PHP 7.0 or higher
- A web server (Apache, Nginx, etc.)

### Installation

1. **Download:**
   - Clone the repository or download the `index.php` file.

   ```bash
   git clone https://github.com/HirotakaDango/HDBoard.git
   # or download index.php from GitHub directly
   ```

2. **Deploy:**
   - Place `index.php` in your web server's root directory.

3. **Access:**
   - Open your browser and navigate to your site (e.g., `http://localhost/index.php`).

4. **First run:**
   - The SQLite database (`board.db`) and uploads directory are created automatically on first use.

### Optional Configuration

You can edit `index.php` directly to modify:

- Board title and categories
- Storage path and file size limits
- Posting rules and board/channel names
- UI appearance (CSS is included in the file)
- User role hierarchy and permissions

---

## Folder Structure

```
/HDBoard
├── index.php
└── (Optional) uploads/
```
- **index.php** – Main application file (all logic/UI)
- **uploads/** – Where user uploads are stored (auto-created)

---

## Usage

- **Browse boards:** Click any board from the index to view threads.
- **Register/Login:** Optional – registered users get enhanced features and protections.
- **Post Threads/Replies:** Fill out the form, attach files if desired, and submit.
- **Edit/Delete:** Available for your own posts; moderators/admins can manage all posts.
- **Moderation:** Ban/unban users (janitor+), edit/delete posts, manage users.

---

## Security

- **CSRF protection** for all forms.
- **Sessions** use secure cookie settings.
- **Passwords** stored as bcrypt hashes.
- **Input validation** for usernames, comments, and uploads.

---

## Customization

- **Adding Boards:** Edit the `ALLOWED_CHANNELS`, `CHANNEL_NAMES`, and `$channel_categories` sections in `index.php`.
- **Appearance:** All CSS is in the file; tweak to your liking.
- **Limits:** Adjust `MAX_FILE_SIZE`, allowed file extensions, etc.

---

## Credits

- Inspired by [4chan](https://4chan.org/) and classic imageboards.
- Created by [HirotakaDango](https://github.com/HirotakaDango).
- Contributions and feedback are welcome!

---

## Disclaimer

Use responsibly. Some channels may be NSFW. You are responsible for the content and moderation on your deployed instance.
