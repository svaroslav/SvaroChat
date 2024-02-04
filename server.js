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

// Custom console logging function
function enableConsoleTimestamps() {
    // Keep the system one
    const systemLog = console.log;
    const systemWarn = console.warn;
    const systemError = console.error;

    console.log = function (...args) {
        const timestamp = new Date().toUTCString();
        systemLog.call(console, '[' + timestamp + ']', ...args);
    };
    console.warn = function (...args) {
        const timestamp = new Date().toUTCString();
        systemWarn.call(console, '[' + timestamp + ']', ...args);
    };
    console.error = function (...args) {
        const timestamp = new Date().toUTCString();
        systemError.call(console, '[' + timestamp + ']', ...args);
    };
}

// Enable timestamps for console outputs
enableConsoleTimestamps();

const app = Express();
// Set EJS as the view engine
app.set('view engine', 'ejs');
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

// In-memory user storage (Replace this with a database in a real-world scenario)
const localUsers = [
    {id: 1, username: 'user', password: 'password', authToken: 'auth'},
    {id: 2, username: 'user1', password: 'password1', authToken: 'auth1'},
    {id: 3, username: 'user2', password: 'password2', authToken: 'auth2'}
];

// Passport strategy for local authentication
Passport.use(new LocalStrategy(
    {
        usernameField: 'username', // Specify the field name for the username
        passwordField: 'password', // Specify the field name for the password
    },
    (username, password, done) => {
        //console.log('Authentication strategy is called for username:', username);
        const user = localUsers.find(u => u.username === username && u.password === password);
        if (user) {
            //console.log('Authentication successful:', user.username);
            return done(null, user);
        } else {
            //console.log('Authentication failed for username:', username);
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
    done(null, user.id);
});

// Deserialize user information from the session
Passport.deserializeUser((id, done) => {
    // Assuming users is an array or some data structure containing user objects
    const user = localUsers.find(u => u.id === id);

    if (user) {
        // If the user is found, pass the user object to done
        done(null, user);
    } else {
        // If the user is not found, pass an error to done
        done(new Error('User not found'));
    }
});

// Serve static files from the 'static' folder
app.use(Express.static('static'));

// Define routes
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        console.log('HTTP [User: ' + req.user.username + '] GET /');
        res.sendFile(__dirname + '/pages/dashboard.html');
    } else {
        console.log('HTTP GET / Not authenticated. Redirecting to login page.');
        res.redirect('/login'); // Redirect to login page if not authenticated
    }
});

app.get('/ws_client.js', (req, res) => {
    console.log('HTTP [User: ' + req.user.username + '] GET /ws_client.js');
    // Render the ws_client.ejs file, passing the token value as a variable
    res.render(__dirname + '/pages/ws_client', { user_auth_token: req.user.authToken });
});

app.get('/login', (req, res) => {
    console.log('HTTP GET /login');
    res.sendFile(__dirname + '/pages/login.html');
});

app.post('/login', (req, res, next) => {
    console.log('HTTP POST /login');
    Passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error(err);
            return next(err);
        }
        if (!user) {
            console.log('HTTP Authentication of username (' + req.body['username'] + ') failed:', info.message);
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error(err);
                return next(err);
            }
            console.log('HTTP [User: ' + user.username + '] Authenticated');
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', (req, res) => {
    console.log('HTTP [User: ' + req.user.username + '] GET /logout');
    req.logout((err) => {
        if (err) {
            console.log('HTTP Error logging out');
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
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
        console.log('WS [User: ' + user.username + '] Connected');

        // Handle WebSocket messages
        ws.on('message', (message) => {
            // Handle connection keep-alive
            if (message == 'ping') {
                ws.send('pong')
            } else {
                // Associate the message with the authenticated user
                const user = getUserByWebsocketConnection(ws);
                console.log('WS [User: ' + user.username + '] Sent message ' + message);
                // Send a response back to the user
                sendWebsocketMessageToUser(user.id, message);
            }
        });

        // Handle Websocket disconnection
        ws.on('close', () => {
            const user = getUserByWebsocketConnection(ws);
            handleWebsocketDisconnect(user.id, ws);
            console.log('WS [User: ' + user.username + '] Disconnected');
        });
    } else {
        // Non-authenticated user, close the connection or handle as needed
        console.log('WS User not authenticated');
        ws.send('Invalid authentication');
        ws.close();
    }
});

// Send Websocket message to all connections of same user
function sendWebsocketMessageToUser(userId, message) {
    for (const [userId, userConnection] of userSocketMap) {
        for (const ws of userConnection) {
            const user = getUserByID(userId);
            ws.send(user.username + ': ' + message);
        }
    }
}

// Check if the new connection on websocket is coming from authenticated user
function authenticateWebsocket(ws, authToken) {
    // Get the local user corresponding to provided authToken
    const user = localUsers.find(u => u.authToken === authToken);

    if (user) {
        // If the user is found, map it to this connection
        // Check if the user ID is already in the map
        if (userSocketMap.has(user.id)) {
            // If it is, add the new Websocket connection to the existing array
            const existingConnections = userSocketMap.get(user.id);
            existingConnections.push(ws);
        } else {
            // If it's not, create a new array with the WebSocket connection
            userSocketMap.set(user.id, [ws]);
        }
        return true;
    } else {
        // If the user is not found
        return false;
    }
}

// Handle websocket client disconnecting
function handleWebsocketDisconnect(userId, disconnectedWs) {
    if (userSocketMap.has(userId)) {
        const existingConnections = userSocketMap.get(userId);
        // Remove the disconnected WebSocket from the array
        userSocketMap.set(
            userId,
            existingConnections.filter((ws) => ws !== disconnectedWs)
        );

        // If there are no more connections for the user, you can remove the entry
        if (existingConnections.length === 1 && existingConnections[0] === disconnectedWs) {
            userSocketMap.delete(userId);
        }
    }
}

// Gets the user's object from websocket to user map
function getUserByWebsocketConnection(connection) {
    for (const [userId, userConnection] of userSocketMap) {
        if (userConnection.includes(connection)) {
            const user = localUsers.find(u => u.id === userId);
            return user;
        }
    }
    
    // If the connection is not found, return null or handle accordingly
    console.log('WS Failed to get user by Websocket connection');
    return null;
}

// Get user object by its id
function getUserByID(userId) {
    const user = localUsers.find(u => u.id === userId);
    return user;
}

server.listen(8080, () => {
    console.log('Server is listening on port 8080');
});
