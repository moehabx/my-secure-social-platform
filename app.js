require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const sanitizeHTML = require("sanitize-html");
const db = require("better-sqlite3")("ourApp.db");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const marked = require("marked");
const multer = require("multer");
const path = require("path");
const http = require("http");
const socketIO = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

db.pragma("synchronous = FULL");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const createTables = db.transaction(() => {
    db.prepare(
        `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        isAdmin BOOLEAN DEFAULT 0,
        profilePicture TEXT
        )`
    ).run();
    db.prepare(
        `CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        image TEXT,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users(id)
        )`
    ).run();
    db.prepare(
        `CREATE TABLE IF NOT EXISTS likes (
        userId INTEGER,
        postId INTEGER,
        PRIMARY KEY (userId, postId),
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (postId) REFERENCES posts(id)
        )`
    ).run();
    db.prepare(
        `CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        createdDate TEXT,
        userId INTEGER,
        postId INTEGER,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (postId) REFERENCES posts(id)
        )`
    ).run();
    db.prepare(
        `CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        createdDate TEXT NOT NULL,
        senderId INTEGER,
        receiverId INTEGER,
        FOREIGN KEY (senderId) REFERENCES users(id),
        FOREIGN KEY (receiverId) REFERENCES users(id)
        )`
    ).run();
});
createTables();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/uploads");
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb(new Error("Only images (jpeg, jpg, png, gif) are allowed"));
        }
    },
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.render(req.path.includes("profile") ? "profile" : req.path.includes("edit-post") ? "edit-post" : "create-post", {
            errors: [err.message],
            post: req.path.includes("edit-post") ? db.prepare("SELECT * FROM posts WHERE id = ?").get(req.params.id) : null
        });
    } else if (err) {
        req.fileValidationError = err;
        next();
    } else {
        next();
    }
});

app.use((req, res, next) => {
    res.locals.filterUserHTML = function (content) {
        return sanitizeHTML(marked.parse(content), {
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
            allowedAttributes: {}
        });
    };
    res.locals.formatDate = function (dateString) {
        if (!dateString) return "No Date";
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return "Invalid Date";
        return date.toLocaleDateString("en-US", {
            year: "numeric",
            month: "2-digit",
            day: "2-digit"
        });
    };
    res.locals.errors = [];
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
        req.user = decoded;
        if (decoded.userid) {
            const user = db.prepare("SELECT profilePicture FROM users WHERE id = ?").get(decoded.userid);
            req.user.profilePicture = user.profilePicture || "/default-profile.png";
        }
    } catch (err) {
        req.user = false;
    }
    res.locals.user = req.user;
    next();
});

function mustBeLoggedIn(req, res, next) {
    if (req.user) {
        return next();
    }
    return res.redirect("/");
}

function mustBeAdmin(req, res, next) {
    if (req.user && req.user.isAdmin) {
        return next();
    }
    return res.redirect("/");
}

function sharedPostValidation(req) {
    const errors = [];
    if (typeof req.body.title !== "string") req.body.title = "";
    if (typeof req.body.body !== "string") req.body.body = "";
    req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} });
    req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} });
    if (!req.body.title) errors.push("You must provide a title");
    if (!req.body.body) errors.push("You must provide a body");
    if (req.body.title.length < 2) errors.push("Title must be at least 2 characters long");
    if (req.body.body.length < 2) errors.push("Body must be at least 2 characters long");
    return errors;
}

function sharedCommentValidation(req) {
    const errors = [];
    if (typeof req.body.content !== "string") req.body.content = "";
    req.body.content = sanitizeHTML(req.body.content.trim(), { allowedTags: [], allowedAttributes: {} });
    if (!req.body.content) errors.push("You must provide comment content");
    if (req.body.content.length < 2) errors.push("Comment must be at least 2 characters long");
    if (req.body.content.length > 500) errors.push("Comment cannot exceed 500 characters");
    return errors;
}

function sharedMessageValidation(content) {
    const errors = [];
    if (typeof content !== "string") content = "";
    content = sanitizeHTML(content.trim(), { allowedTags: [], allowedAttributes: {} });
    if (!content) errors.push("Message content is required");
    if (content.length < 1) errors.push("Message must be at least 1 character long");
    if (content.length > 1000) errors.push("Message cannot exceed 1000 characters");
    return { content, errors };
}

// Socket.IO Authentication and Chat Handling
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication token missing'));
    }

    try {
        const decoded = jwt.verify(token, process.env.JWTSECRET);
        socket.user = decoded; // { userid, username, isAdmin }
        next();
    } catch (err) {
        next(new Error('Invalid authentication token'));
    }
});

io.on("connection", (socket) => {
    console.log(`User ${socket.user.username} connected`);

    // Join user-specific room immediately
    socket.join(`user_${socket.user.userid}`);

    socket.on("chatMessage", (data) => {
        console.log("Received chatMessage event:", data);
        const { receiverId: receiverIdStr, content } = data;
        const receiverId = parseInt(receiverIdStr, 10); // Convert to integer

        if (isNaN(receiverId)) {
            console.log("Invalid receiverId:", receiverIdStr);
            socket.emit("chatError", { errors: ["Invalid recipient ID"] });
            return;
        }

        // Validate message
        const validation = sharedMessageValidation(content);
        if (validation.errors.length) {
            console.log("Validation errors:", validation.errors);
            socket.emit("chatError", { errors: validation.errors });
            return;
        }

        // Check if receiver exists
        const receiverExists = db.prepare("SELECT id FROM users WHERE id = ?").get(receiverId);
        if (!receiverExists) {
            console.log("Receiver does not exist:", receiverId);
            socket.emit("chatError", { errors: ["Recipient does not exist"] });
            return;
        }

        // Insert message
        const insertStatement = db.prepare(
            "INSERT INTO messages (content, createdDate, senderId, receiverId) VALUES (?, ?, ?, ?)"
        );
        let result;
        try {
            result = insertStatement.run(
                validation.content,
                new Date().toISOString(),
                socket.user.userid,
                receiverId
            );
            if (result.changes === 0) {
                console.error("No rows inserted, possible constraint violation");
                socket.emit("chatError", { errors: ["Failed to save message"] });
                return;
            }
        } catch (error) {
            console.error("Insertion error:", error);
            socket.emit("chatError", { errors: ["Failed to save message"] });
            return;
        }

        // Retrieve and broadcast message
        const message = db.prepare(`
            SELECT messages.*, users.username AS senderUsername 
            FROM messages 
            INNER JOIN users ON messages.senderId = users.id 
            WHERE messages.id = ?
        `).get(result.lastInsertRowid);

        if (!message) {
            console.error("Failed to retrieve inserted message");
            socket.emit("chatError", { errors: ["Failed to retrieve message"] });
            return;
        }

        io.to(`user_${socket.user.userid}`)
            .to(`user_${receiverId}`)
            .emit("chatMessage", {
                id: message.id,
                content: message.content,
                createdDate: message.createdDate,
                senderId: message.senderId,
                senderUsername: message.senderUsername,
                receiverId: message.receiverId
            });
    });

    socket.on("disconnect", () => {
        console.log(`User ${socket.user.username} disconnected`);
    });
});

// Routes
app.get("/", (req, res) => {
    let posts;
    if (req.user) {
        const postsStatement = db.prepare(`
            SELECT posts.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture,
                   (SELECT COUNT(*) FROM likes WHERE likes.postId = posts.id) AS likeCount,
                   EXISTS (SELECT 1 FROM likes WHERE likes.postId = posts.id AND likes.userId = ?) AS hasLiked,
                   (SELECT COUNT(*) FROM comments WHERE comments.postId = posts.id) AS commentCount
            FROM posts
            INNER JOIN users ON posts.authorid = users.id
            ORDER BY posts.id DESC
        `);
        posts = postsStatement.all(req.user ? req.user.userid : 0);
        return res.render("dashboard", { posts });
    }
    res.render("homepage");
});

app.get("/login", (req, res) => {
    res.render("login", { errors: [] });
});

app.get("/logout", mustBeLoggedIn, (req, res) => {
    res.clearCookie("ourSimpleApp");
    res.redirect("/");
});

app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post", { errors: [] });
});

app.get("/post/:id", mustBeLoggedIn, (req, res) => {
    const postStatement = db.prepare(`
        SELECT posts.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture,
               (SELECT COUNT(*) FROM likes WHERE likes.postId = posts.id) AS likeCount,
               EXISTS (SELECT 1 FROM likes WHERE likes.postId = posts.id AND likes.userId = ?) AS hasLiked,
               (SELECT COUNT(*) FROM comments WHERE comments.postId = posts.id) AS commentCount
        FROM posts
        INNER JOIN users ON posts.authorid = users.id
        WHERE posts.id = ?
    `);
    const post = postStatement.get(req.user.userid, req.params.id);

    if (!post) {
        return res.redirect("/");
    }

    const commentsStatement = db.prepare(`
        SELECT comments.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture
        FROM comments
        INNER JOIN users ON comments.userId = users.id
        WHERE comments.postId = ?
        ORDER BY comments.createdDate ASC
    `);
    const comments = commentsStatement.all(req.params.id);

    const isAuthor = post.authorid === req.user.userid;
    const isAdmin = req.user.isAdmin || false;
    res.render("single-post", { post, comments, isAuthor, isAdmin });
});

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);
    if (!post) {
        return res.redirect("/");
    }

    if (post.authorid !== req.user.userid && !req.user.isAdmin) {
        return res.redirect("/");
    }
    
    res.render("edit-post", { post, errors: [] });
});

app.get("/my-posts", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare(`
        SELECT posts.*, 
               (SELECT COUNT(*) FROM likes WHERE likes.postId = posts.id) AS likeCount,
               EXISTS (SELECT 1 FROM likes WHERE likes.postId = posts.id AND likes.userId = ?) AS hasLiked,
               (SELECT COUNT(*) FROM comments WHERE comments.postId = posts.id) AS commentCount
        FROM posts
        WHERE posts.authorid = ?
        ORDER BY posts.id DESC
    `);
    const posts = statement.all(req.user.userid, req.user.userid);
    let postedBefore = posts.length > 0;
    res.render("my-posts", { postedBefore, posts });
});

app.get("/admin-dashboard", mustBeAdmin, (req, res) => {
    const postsStatement = db.prepare(`
        SELECT posts.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture,
               (SELECT COUNT(*) FROM likes WHERE likes.postId = posts.id) AS likeCount
        FROM posts
        INNER JOIN users ON posts.authorid = users.id
        ORDER BY posts.id DESC
    `);
    const posts = postsStatement.all();
    const usersStatement = db.prepare("SELECT id, username, isAdmin, COALESCE(profilePicture, '/default-profile.png') AS profilePicture FROM users ORDER BY id");
    const users = usersStatement.all();
    const commentsStatement = db.prepare(`
        SELECT comments.*, posts.title AS postTitle, users.username
        FROM comments
        INNER JOIN posts ON comments.postId = posts.id
        INNER JOIN users ON comments.userId = users.id
        ORDER BY comments.createdDate DESC
    `);
    const comments = commentsStatement.all();
    res.render("admin-dashboard", { posts, users, comments });
});

app.get("/profile", mustBeLoggedIn, (req, res) => {
    res.render("profile", { errors: [] });
});

app.get("/chat", mustBeLoggedIn, (req, res) => {
    const users = db.prepare("SELECT id, username, COALESCE(profilePicture, '/default-profile.png') AS profilePicture FROM users WHERE id != ?").all(req.user.userid);
    const token = req.cookies.ourSimpleApp;
    res.render("chat", { users, errors: [], token });
});

app.get("/chat/:receiverId", mustBeLoggedIn, (req, res) => {
    const receiverId = parseInt(req.params.receiverId, 10);
    if (isNaN(receiverId)) {
        return res.redirect("/chat");
    }

    const receiver = db.prepare(`
        SELECT id, username, COALESCE(profilePicture, '/default-profile.png') AS profilePicture 
        FROM users 
        WHERE id = ?
    `).get(receiverId);
    if (!receiver) {
        return res.redirect("/chat");
    }

    const messages = db.prepare(`
        SELECT m.*, u.username AS senderUsername
        FROM messages m
        INNER JOIN users u ON m.senderId = u.id
        WHERE (m.senderId = ? AND m.receiverId = ?) OR (m.senderId = ? AND m.receiverId = ?)
        ORDER BY m.createdDate ASC
    `).all(req.user.userid, receiverId, receiverId, req.user.userid);

    const users = db.prepare(`
        SELECT id, username, COALESCE(profilePicture, '/default-profile.png') AS profilePicture 
        FROM users 
        WHERE id != ?
    `).all(req.user.userid);

    const token = req.cookies.ourSimpleApp;
    res.render("chat", { users, receiver, messages, errors: [], token });
});

app.post("/profile", mustBeLoggedIn, upload.single("profilePicture"), (req, res) => {
    let errors = [];
    if (!req.file) {
        errors.push("No file uploaded or invalid file type");
        return res.render("profile", { errors });
    }

    const filePath = `/uploads/${req.file.filename}`;
    const updateStatement = db.prepare("UPDATE users SET profilePicture = ? WHERE id = ?");
    updateStatement.run(filePath, req.user.userid);

    req.user.profilePicture = filePath;

    res.redirect("/profile");
});

app.post("/like/:id", mustBeLoggedIn, (req, res) => {
    const postId = req.params.id;
    const userId = req.user.userid;
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(postId);

    if (!post) {
        return res.redirect("/");
    }

    const insertStatement = db.prepare("INSERT OR IGNORE INTO likes (userId, postId) VALUES (?, ?)");
    insertStatement.run(userId, postId);

    res.redirect(req.headers.referer || `/post/${postId}`);
});

app.post("/unlike/:id", mustBeLoggedIn, (req, res) => {
    const postId = req.params.id;
    const userId = req.user.userid;
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(postId);

    if (!post) {
        return res.redirect("/");
    }

    const deleteStatement = db.prepare("DELETE FROM likes WHERE userId = ? AND postId = ?");
    deleteStatement.run(userId, postId);

    res.redirect(req.headers.referer || `/post/${postId}`);
});

app.post("/comment/:postId", mustBeLoggedIn, (req, res) => {
    const postId = req.params.postId;
    const userId = req.user.userid;
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(postId);

    if (!post) {
        return res.redirect("/");
    }

    const errors = sharedCommentValidation(req);
    if (errors.length) {
        const postStatement = db.prepare(`
            SELECT posts.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture,
                   (SELECT COUNT(*) FROM likes WHERE likes.postId = posts.id) AS likeCount,
                   EXISTS (SELECT 1 FROM likes WHERE likes.postId = posts.id AND likes.userId = ?) AS hasLiked,
                   (SELECT COUNT(*) FROM comments WHERE comments.postId = posts.id) AS commentCount
            FROM posts
            INNER JOIN users ON posts.authorid = users.id
            WHERE posts.id = ?
        `);
        const postData = postStatement.get(req.user.userid, postId);
        const commentsStatement = db.prepare(`
            SELECT comments.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture
            FROM comments
            INNER JOIN users ON comments.userId = users.id
            WHERE comments.postId = ?
            ORDER BY comments.createdDate ASC
        `);
        const comments = commentsStatement.all(postId);
        const isAuthor = postData.authorid === req.user.userid;
        const isAdmin = req.user.isAdmin || false;
        return res.render("single-post", { post: postData, comments, isAuthor, isAdmin, errors });
    }

    const insertStatement = db.prepare("INSERT INTO comments (content, createdDate, userId, postId) VALUES (?, ?, ?, ?)");
    insertStatement.run(req.body.content, new Date().toISOString(), userId, postId);

    res.redirect(`/post/${postId}`);
});

app.post("/delete-comment/:commentId", mustBeLoggedIn, (req, res) => {
    const commentId = req.params.commentId;
    const statement = db.prepare("SELECT * FROM comments WHERE id = ?");
    const comment = statement.get(commentId);

    if (!comment) {
        return res.redirect("/");
    }

    if (comment.userId !== req.user.userid && !req.user.isAdmin) {
        return res.redirect("/");
    }

    const deleteStatement = db.prepare("DELETE FROM comments WHERE id = ?");
    deleteStatement.run(commentId);

    res.redirect(req.headers.referer || "/");
});

app.post("/create-post", mustBeLoggedIn, upload.single("postImage"), (req, res) => {
    const errors = sharedPostValidation(req);
    if (req.fileValidationError) {
        errors.push(req.fileValidationError.message);
    }

    if (errors.length) {
        return res.render("create-post", { errors });
    }

    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
    const ourStatement = db.prepare("INSERT INTO posts (title, body, image, authorid, createdDate) VALUES (?, ?, ?, ?, ?)");
    const result = ourStatement.run(req.body.title, req.body.body, imagePath, req.user.userid, new Date().toISOString());
    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
    const realPost = getPostStatement.get(result.lastInsertRowid);
    res.redirect(`post/${realPost.id}`);
});

app.post("/edit-post/:id", mustBeLoggedIn, upload.single("postImage"), (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);
    if (!post) {
        return res.redirect("/");
    }

    if (post.authorid !== req.user.userid && !req.user.isAdmin) {
        return res.redirect("/");
    }
    const errors = sharedPostValidation(req);
    if (req.fileValidationError) {
        errors.push(req.fileValidationError.message);
    }
    if (errors.length) {
        return res.render("edit-post", { errors, post });
    }

    const imagePath = req.file ? `/uploads/${req.file.filename}` : post.image;
    const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ?, image = ? WHERE id = ?");
    updateStatement.run(req.body.title, req.body.body, imagePath, req.params.id);
    res.redirect(`/post/${req.params.id}`);
});

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);
    if (!post) {
        return res.redirect("/");
    }

    if (post.authorid !== req.user.userid && !req.user.isAdmin) {
        return res.redirect("/");
    }
    const deleteLikes = db.prepare("DELETE FROM likes WHERE postId = ?");
    deleteLikes.run(req.params.id);
    const deleteComments = db.prepare("DELETE FROM comments WHERE postId = ?");
    deleteComments.run(req.params.id);
    const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?");
    deleteStatement.run(req.params.id);
    res.redirect(req.user.isAdmin ? "/admin-dashboard" : "/");
});

app.post("/admin/delete-user/:id", mustBeAdmin, (req, res) => {
    const userId = req.params.id;
    if (userId == req.user.userid) {
        return res.render("admin-dashboard", {
            errors: ["You cannot delete your own account"],
            posts: db.prepare(`
                SELECT posts.*, users.username, COALESCE(users.profilePicture, '/default-profile.png') AS profilePicture,
                       (SELECT COUNT(*) FROM likes WHERE likes.postId = posts.id) AS likeCount
                FROM posts
                INNER JOIN users ON posts.authorid = users.id
                ORDER BY posts.id DESC
            `).all(),
            users: db.prepare("SELECT id, username, isAdmin, COALESCE(profilePicture, '/default-profile.png') AS profilePicture FROM users ORDER BY id").all(),
            comments: db.prepare(`
                SELECT comments.*, posts.title AS postTitle, users.username
                FROM comments
                INNER JOIN posts ON comments.postId = posts.id
                INNER JOIN users ON comments.userId = users.id
                ORDER BY comments.createdDate DESC
            `).all()
        });
    }
    const deletePosts = db.prepare("DELETE FROM posts WHERE authorid = ?");
    deletePosts.run(userId);
    const deleteLikes = db.prepare("DELETE FROM likes WHERE userId = ?");
    deleteLikes.run(userId);
    const deleteComments = db.prepare("DELETE FROM comments WHERE userId = ?");
    deleteComments.run(userId);
    const deleteMessages = db.prepare("DELETE FROM messages WHERE senderId = ? OR receiverId = ?");
    deleteMessages.run(userId, userId);
    const deleteUser = db.prepare("DELETE FROM users WHERE id = ?");
    deleteUser.run(userId);
    res.redirect("/admin-dashboard");
});

app.post("/login", (req, res) => {
    let errors = [];
    const { username, password } = req.body;
    
    if (typeof username !== "string" || typeof password !== "string") {
        errors.push("Invalid input");
    }
    
    if (!username.trim() || !password) {
        errors.push("Username and password are required");
    }
    
    if (username.length < 3 || username.length > 10) {
        errors.push("Username must be between 3 and 10 characters");
    }
    
    if (!/^[a-zA-Z0-9]+$/.test(username)) {
        errors.push("Username can only contain letters and numbers");
    }
    
    if (errors.length) {
        return res.render("login", { errors });
    }
    
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.render("login", { errors: ["Invalid username or password"] });
    }
    
    const token = jwt.sign({ userid: user.id, username: user.username, isAdmin: user.isAdmin }, process.env.JWTSECRET, { expiresIn: "1d" });
    
    res.cookie("ourSimpleApp", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 86400000
    });
    
    res.redirect("/");
});

app.post("/register", (req, res) => {
    let errors = [];
    const { username, password } = req.body;
    
    if (typeof username !== "string" || typeof password !== "string") {
        errors.push("Invalid input");
    }
    
    if (!username.trim() || !password) {
        errors.push("Username and password are required");
    }
    
    if (username.length < 3 || username.length > 10) {
        errors.push("Username must be between 3 and 10 characters");
    }
    
    if (!/^[a-zA-Z0-9]+$/.test(username)) {
        errors.push("Username can only contain letters and numbers");
    }
    
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?");
    const usernameCheck = usernameStatement.get(username);
    if (usernameCheck) errors.push("That username already exists");

    if (errors.length) {
        return res.render("homepage", { errors });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = db.prepare("INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)").run(username, hashedPassword, 0);
    
    const newUser = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    const token = jwt.sign({ userid: newUser.id, username: newUser.username, isAdmin: newUser.isAdmin }, process.env.JWTSECRET, { expiresIn: "1d" });
    
    res.cookie("ourSimpleApp", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 86400000
    });
    
    res.redirect("/");
});

server.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});