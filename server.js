const Express = require('express');
const Ejs = require('ejs');
const BodyParser = require('body-parser');
const Http = require('http');
const WebSocket = require('ws');
const Session = require('express-session');
const Passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const Url = require('url');
const Winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const Mysql = require('mysql2/promise');
const MysqlSync = require('sync-mysql');
const Path = require('path');

// Define a custom format for the log entries
const customFormat = Winston.format.printf(({ level, message, timestamp }) => {
    return `[${timestamp}] ${level.toUpperCase()} ${message}`;
});

// Create a Winston logger
const logger = Winston.createLogger({
    level: 'debug', // Set the log level to debug

    transports: [
        // Log to the console
        new Winston.transports.Console({
            format: Winston.format.combine(
                Winston.format.timestamp({ format: 'ddd, DD MMM YYYY HH:mm:ss' }), // Custom timestamp format
                customFormat
            ),
        }),

        // Log to a file with daily rotation
        new DailyRotateFile({
            filename: 'logs/server-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m', // Maximum log file size before rotation
            maxFiles: '14d', // Keep logs for 14 days
            format: Winston.format.combine(
                Winston.format.timestamp({ format: 'ddd, DD MMM YYYY HH:mm:ss' }), // Custom timestamp format
                customFormat
            ),
        }),
    ],
});

// Make sure to close the logger when your application exits
process.on('exit', () => {
    // If necessary, perform any cleanup here
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    logger.error(`Uncaught Exception: ${err.message}`);
    process.exit(1); // Exit with an error code
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    logger.error(`Unhandled Rejection: ${reason}`);
    process.exit(1); // Exit with an error code
});

// Starting app
logger.info('Starting server');

// DB connection info for synchronous queries
const mysqlSyncConnInfo = {
    host: '192.168.0.4',
    port: 3307,
    user: 'svarochat',
    password: 'NA4aNOfiBocE.',
    database: 'svarochat'
};
// Create a synchronous connection to the database
logger.info('Connecting to the database');
const connSync = new MysqlSync(mysqlSyncConnInfo);

// Create a async MySQL pool
// const pool = Mysql.createPool({
//     host: '192.168.0.4',
//     port: 3307,
//     user: 'svarochat',
//     password: 'NA4aNOfiBocE.',
//     database: 'svarochat',
//     waitForConnections: true,
//     connectionLimit: 10,
//     queueLimit: 0
// });

// Setup server
const app = Express();
// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', __dirname + '/pages');
const server = Http.createServer(app);
const wss = new WebSocket.Server({server});

app.use(BodyParser.urlencoded({extended: true})); // Parse URL-encoded bodies

// Use express-session middleware to manage user sessions
app.use(Session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
}));

// Initialize passport and use passport session
app.use(Passport.initialize());
app.use(Passport.session());

// Passport strategy for local authentication
Passport.use(new LocalStrategy(
    {
        usernameField: 'username', // Specify the field name for the username
        passwordField: 'password', // Specify the field name for the password
    },
    (username, password, done) => {
        //logger.info('Authentication strategy is called for username:', username);
        const user = authenticateUser(username, password);
        if (user) {
            //logger.info('Authentication successful:', user.username);
            return done(null, user);
        } else {
            //logger.info('Authentication failed for username:', username);
            return done(null, false, {message: 'Incorrect username or password'});
        }
    }
));

// Configure Google OAuth strategy
Passport.use(new GoogleStrategy({
        clientID: 'your-client-id',
        clientSecret: 'your-client-secret',
        callbackURL: 'https://chat.svaro.cz/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
    // Use the profile information (e.g., profile.id, profile.displayName, profile.emails[0].value)
    // to find or create a user in your database
    // You can customize this based on your application's user model

    return done(null, profile);
}));

// Google login initiator endpoint
app.get('/auth/google',
    Passport.authenticate('google', {scope: ['profile', 'email']})
);

// Return endpoint for google-authenticated users
app.get('/auth/google/callback',
    Passport.authenticate('google', {failureRedirect: '/'}),
    (req, res) => {
        // Successful authentication, redirect home
        res.redirect('/');
    }
);

// Serialize user information into the session
Passport.serializeUser((user, done) => {
    if (user && user.Username) {
        logger.debug('SerializeUser: ' + user.Username);
        done(null, user.Username);
    } else {
        done(new Error('User object or Username not available'));
    }
});
  
// Deserialize user information from the session
Passport.deserializeUser((username, done) => {
try {
    logger.debug('DeserializeUser: ' + username);
    // Get user information from the database
    const rows = connSync.query('SELECT * FROM Users WHERE Username = ?', [username]);

    if (rows.length > 0) {
        // If the user is found, pass the user object to done
        done(null, rows[0]);
    } else {
        // If the user is not found, pass an error to done
        done(new Error('User not found'));
    }
} catch (error) {
    // Handle database errors
    done(error);
}
});
  
// Fetch users from the database and compare passwords during authentication
function authenticateUser(username, password) {
    try {
        logger.debug('AuthenticateUser: ' + username);

        // Fetch user from the database based on the username
        const result = connSync.query('SELECT * FROM Users WHERE Username = ?', [username]);
    
        if (result.length > 0) {
            const user = result[0];
    
            // Compare passwords
            if (password === user.Password) {
                return user; // Authentication successful
            }
        }
    
        return null; // User not found or password mismatch
    } catch (error) {
        // Handle database errors
        throw error;
    }
}
  
// Fetch user data from the database
function getUser(username) {
    try {
        logger.debug('GetUser: ' + username);
        // Fetch user from the database based on the username
        const rows = connSync.query('SELECT * FROM Users WHERE Username = ?', [username]);
        
        if (rows.length > 0) {
            const user = rows[0];
    
            return user;
        }
    
        return null; // User not found
    } catch (error) {
        // Handle database errors
        throw error;
    }
}
  
// Fetch user's chats from the database
function getUserChats(username) {
    try {
        logger.debug('GetUserChats: ' + username);
        // Fetch user's chats from the database based on the username
        const chats = connSync.query('SELECT Chats.* FROM Chats, UsersToChats WHERE UsersToChats.Username = ?', [username]);
        
        if (chats.length > 0) {
            return chats;
        }
    
        return null; // User not found
    } catch (error) {
        // Handle database errors
        throw error;
    }
}

// Fetch user's chats from the database
function getChatMessages(chatId, timestampFrom = 0, timestampTo = new Date().getTime()) {
    try {
        logger.debug('GetChatMessages: ' + chatId + ' <' + timestampFrom / 1000 + ', ' + timestampTo / 1000 + '>');
        // Fetch user's chats from the database based on the username
        const messages = connSync.query('SELECT * FROM Messages WHERE ChatId = ? AND Sent BETWEEN FROM_UNIXTIME(?) AND FROM_UNIXTIME(?) ORDER BY Sent', [chatId, timestampFrom / 1000, timestampTo / 1000]);
        logger.debug('Found ' + messages.length + ' messages');
        
        if (messages.length > 0) {
            return messages;
        }
    
        return null; // User not found
    } catch (error) {
        // Handle database errors
        throw error;
    }
}

// Fetch info about selected chat room from the database
function getChatInfo(chatId) {
    try {
        logger.debug('GetChatInfo: ' + chatId);
        // Fetch user's chats from the database based on the username
        const chatInfo = connSync.query('SELECT * FROM Chats WHERE Id = ?', [chatId]);
        const userList = connSync.query('SELECT * FROM UsersToChats WHERE ChatId = ?', [chatId]);
        
        if (chatInfo.length > 0 && userList.length > 0) {
            const info = {Info: chatInfo[0], Members: userList};
            return info;
        }
    
        return null; // User not found
    } catch (error) {
        // Handle database errors
        throw error;
    }
}
  
// Fetch user data from the database
function getUserByAuthToken(authToken) {
    try {
        // Fetch user from the database based on the username
        const rows = connSync.query('SELECT * FROM Users WHERE AuthToken = ?', [authToken]);
        
        if (rows.length > 0) {
            const user = rows[0];
            logger.debug('GetUserByAuthToken - user: ', user.Username);
    
            return user;
        }
    
        logger.warn('Failed to get user by authToken');
        return null; // User not found
    } catch (error) {
        // Handle database errors
        throw error;
    }
}
  
// Fetch user's chats from the database
function createNewChat(ownerUsername, chatTitle) {
    try {
        logger.debug('CreateNewChat (' + ownerUsername + '): ' + chatTitle);
        // Insert new chat into chats table
        const result = connSync.query('INSERT INTO Chats (Title) VALUES (?)', [chatTitle]);
        console.log(result);
        
        // Link created chat to its owner user
        //const result1 = connSync.query('INSERT INTO UsersToChats (Username, ChatId) VALUES (?, ?)', [ownerUsername, 1]);
        //console.log(result1);
        
        if (chats.length > 0) {
            return chats;
        }
    
        return false; // Insertion failed
    } catch (error) {
        // Handle database errors
        throw error;
    }
}

// Serve static files from the 'static' folder
app.use('/static', Express.static(Path.join(__dirname, 'static'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        } else if (filePath.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        }
    },
}));

// Main page route
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        logger.info('HTTP [User: ' + req.user.Username + '] GET /');

        // Get the id of chat from GET parameter
        const chatId = req.query.chatId;
        var chatMessages = null;
        var currentChat = null;
        if (chatId) {
            req.user.chatId = chatId;

            // Get messages inside that chat
            chatMessages = getChatMessages(chatId);

            // Get information about current chat room
            currentChat = getChatInfo(chatId);
        }

        // Get list of chats of current user
        const userChats = getUserChats(req.user.Username);

        res.render(__dirname + '/pages/chats.html.ejs', {loggedIn: true, user: req.user, chats: userChats, messages: chatMessages, currentChat: currentChat});
    } else {
        logger.info('HTTP GET /');
        res.render(__dirname + '/pages/chats.html.ejs', {loggedIn: false, user: null, chats: null, messages: null});
    }
});

// Create or edit commands route
app.get('/tools', (req, res) => {
    if (req.isAuthenticated()) {
        logger.info('HTTP [User: ' + req.user.Username + '] GET /tools');

        // Get the command from GET parameter
        const command = req.query.command;
        if (command) {

        }

        if (command == 'createChat') {
            // Get the new chat title from GET parameter
            const chatTitle = req.query.title;
            if (chatTitle) {

            }
        }



    } else {
        // If is not logged in, redirect to main page
        res.redirect('/');
    }
});

app.get('/profile', (req, res) => {
    if (req.isAuthenticated()) {
        // Is logged in, render login page
        logger.info('HTTP GET /profile');
        res.render(__dirname + '/pages/profile.html.ejs', { user: req.user });
    } else {
        // If is not logged in, redirect to main page
        res.redirect('/');
    }
});

app.get('/ws_client.js', (req, res) => {
    logger.info('HTTP [User: ' + req.user.Username + '] GET /ws_client.js');
    // Render the ws_client.ejs file, passing the token value as a variable
    res.setHeader('Content-Type', 'application/javascript');
    res.render(__dirname + '/pages/ws_client.js.ejs', { user_auth_token: req.user.AuthToken, user: req.user });
});

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        // If is logged in, redirect to main page
        res.redirect('/');
    } else {
        // Not logged in, render login page
        logger.info('HTTP GET /login');
        res.render(__dirname + '/pages/login.html.ejs', {  });
    }
});

app.post('/login', (req, res, next) => {
    logger.info('HTTP POST /login');
    Passport.authenticate('local', (err, user, info) => {
        if (err) {
            logger.error(err);
            return next(err);
        }
        if (!user) {
            logger.warn('HTTP Authentication of username (' + req.body['username'] + ') failed:', info.message);
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                logger.error(err);
                return next(err);
            }
            logger.info('HTTP [User: ' + user.Username + '] Authenticated');
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', (req, res) => {
    if (req.isAuthenticated()) {
        const username = req.user.Username;
        logger.info('HTTP [User: ' + username + '] GET /logout');
        req.logout((err) => {
            if (err) {
                logger.warn('HTTP Error logging out');
                return res.status(500).send('Error logging out');
            }
            logger.info('HTTP [User: ' + username + '] Logged out');
            res.redirect('/login');
        });
    } else {
        res.redirect('/login');
    }
});

// Websocket connection mapping user ID to Websocket connection
const userSocketMap = new Map();

wss.on('connection', (ws, req) => {
    // Extract url get argument from the Websocket request
    const query = Url.parse(req.url, true).query;
    const authToken = query['auth-token'];

    // Check authentication based on the authToken
    if (authenticateWebsocket(ws, authToken)) {
        const user = getUserByWebsocketConnection(ws);
        logger.info('WS [User: ' + user.Username + '] Connected');

        // Handle WebSocket messages
        ws.on('message', (message) => {
            // Handle connection keep-alive
            if (message == 'ping') {
                ws.send('pong')
            } else {
                // Associate the message with the authenticated user
                const user = getUserByWebsocketConnection(ws);
                const messageJson = JSON.parse(message);
                if (messageJson) {
                    logger.info('WS [User: ' + user.Username + '] Sent message [ChatId: ' + messageJson.chatId + '] ' + messageJson.text);
                    // Send message to al users in chat
                    messageJson.Username = user.Username;
                    messageJson.Send = new Date().getTime();
                    sendWebsocketMessageToUsersInChat(messageJson.chatId, messageJson);
                } else {
                    logger.info('WS [User: ' + user.Username + '] Sent command ' + message);
                }
            }
        });

        // Handle Websocket disconnection
        ws.on('close', () => {
            const user = getUserByWebsocketConnection(ws);
            handleWebsocketDisconnect(user.Username, ws);
            logger.info('WS [User: ' + user.Username + '] Disconnected');
        });
    } else {
        // Non-authenticated user, close the connection or handle as needed
        logger.warn('WS User not authenticated');
        ws.send('Invalid authentication');
        ws.close();
    }
});

// Send Websocket message to all connections of users in specified chat
function sendWebsocketMessageToUsersInChat(chatId, message) {
    logger.debug('SendWebsocketMessageToUsersInChat - chatId: ' + chatId);

    console.log(message);

    // Save message to the database
    const result = connSync.query('INSERT INTO Messages (Username, ChatId, Data, Sent) VALUES (?, ?, ?, FROM_UNIXTIME(?))', [message.Username, chatId, JSON.stringify({text: message.text}), message.Send / 1000]);
    console.log(result);

    // Get list of users in that chat
    const rows = connSync.query('SELECT Username FROM UsersToChats WHERE ChatId = ? AND Removed IS NULL', [chatId]);
    logger.debug('Found ' + rows.length + ' members');

    if (rows.length > 0) {
        for (const [usernameRow, userConnection] of userSocketMap) {
            logger.debug('Checking user: ' + usernameRow);
            if (rows.some(function(row) { return row.Username === usernameRow; })) {
                logger.debug('Sending to connections of user: ' + usernameRow);
                for (const ws of userConnection) {
                    ws.send(JSON.stringify(message));
                }
            }
        }
    } else {
        logger.warn('SendWebsocketMessageToUsersInChat - no users found in chat: ' + chatId);
    }
}

// Check if the new connection on websocket is coming from authenticated user
function authenticateWebsocket(ws, authToken) {
    // Get the local user corresponding to provided authToken
    const user = getUserByAuthToken(authToken);

    if (user) {
        // If the user is found, map it to this connection
        // Check if the user ID is already in the map
        if (userSocketMap.has(user.Username)) {
            // If it is, add the new Websocket connection to the existing array
            const existingConnections = userSocketMap.get(user.Username);
            existingConnections.push(ws);
            logger.debug('AuthenticateWebsocket - add connection to existing user: ' + user.Username);
        } else {
            // If it's not, create a new array with the WebSocket connection
            userSocketMap.set(user.Username, [ws]);
            logger.debug('AuthenticateWebsocket - add new user: ' + user.Username);
        }
        return true;
    } else {
        // If the user is not found
        return false;
    }
}

// Handle websocket client disconnecting
function handleWebsocketDisconnect(username, disconnectedWs) {
    if (userSocketMap.has(username)) {
        logger.debug('HandleWebsocketDisconnect - user: ' + username);
        const existingConnections = userSocketMap.get(username);
        // Remove the disconnected WebSocket from the array
        userSocketMap.set(
            username,
            existingConnections.filter((ws) => ws !== disconnectedWs)
        );

        // If there are no more connections for the user, you can remove the entry
        if (existingConnections.length === 1 && existingConnections[0] === disconnectedWs) {
            userSocketMap.delete(username);
        }
    }
}

// Gets the user's object from websocket to user map
function getUserByWebsocketConnection(connection) {
    for (const [username, userConnection] of userSocketMap) {
        if (userConnection.includes(connection)) {
            logger.debug('GetUserByWebsocketConnection: ' + username);
            const user = getUser(username);
            return user;
        }
    }
    
    // If the connection is not found, return null or handle accordingly
    logger.warn('WS Failed to get user by Websocket connection');
    return null;
}

server.listen(8080, () => {
    logger.info('Server is listening on port 8080');
});
