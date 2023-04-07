const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const mustache = require('mustache');
const MongoClient = require('mongodb').MongoClient;


const options = {
    key: fs.readFileSync('cert/server.key'),
    cert: fs.readFileSync('cert/server.crt'),
};

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

let squeaks;
let credentials;
let sessions;
const mongoURL = 'mongodb+srv://dzenana:pass@wscluster.8gaiuaq.mongodb.net/test';

const app = express();



const sessionMiddleware = async function (req, res, next) {
    try {
        let cookie = req.cookies;
        if (cookie['squeak-session']) {
            cookie = JSON.parse(cookie['squeak-session'])
            let sessionid = cookie.sessionid;
            let username = cookie.username;
            let usernames = await getUsers()
            let existUser = false
            for (let i = 0; i < usernames.length; i++) {
                if (crypto.verify('SHA256', usernames[i].username, publicKey, Buffer.from(username, 'base64'))) {
                    username = usernames[i].username;
                    existUser = true;
                    break;
                }
            }
            if (existUser) {
                await findSession(sessionid)
                    .then((session) => {
                        if (session) {
                            req.session = { 'sessionid': sessionid, 'username': username }
                        }
                    }).catch((error) => {
                        res.end('Error!')
                        console.log(error);
                    })
            }
        }
    } catch (err) {
        console.log(err)
    }
    next()
}

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(sessionMiddleware);

function getExpirationTimeCookie() {
    var today = new Date();
    var time = today.getTime();
    var expireTime = time + 1000 * 1800;
    today.setTime(expireTime);
    return today.toUTCString();
}

async function authenticate(username, password) {
    let user = await credentials.findOne({
        username: username,
        password: password
    });
    return user !== null;
}

async function authenticateUsername(username) {
    let user = await credentials.findOne({
        username: username
    });
    return user !== null;
}

async function addUser(username, password) {
    await credentials.insertOne({ username: username, password: password });
}

async function findSession(sessionid) {
    let re = new RegExp('^[A-Za-z0-9]*$')
    if (re.test(sessionid)) {
        return await sessions.findOne({ id: sessionid });
    }
    return false;
}

async function newSession() {
    let sessionid = crypto.randomBytes(64).toString('hex');
    await sessions.insertOne({ id: sessionid });
    return sessionid;
}

async function invalidateSession(sessionid) {
    return await sessions.findOneAndDelete({ id: sessionid });
}

async function addSqueak(username, recipient, squeak) {
    let options = { weekday: 'short', hour: 'numeric', minute: 'numeric' };
    let time = new Date().toLocaleDateString('sv-SE', options);
    await squeaks.insertOne({
        name: username,
        time: time,
        recipient: recipient,
        squeak: squeak
    });
}

async function getSqueaks(recipient) {
    return await squeaks.find({ recipient: recipient }).toArray();
}

async function getUsers() {
    return await credentials.find({}).toArray();
}

app.get('/', async (req, res) => {
    if (!req.session) {
        let template = fs.readFileSync('./templates/signin.mustache').toString('UTF-8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(mustache.render(template));
    } else {
        let username = req.session['username'];
        Promise.all([getUsers(), getSqueaks('all'), getSqueaks(username),])
            .then(results => {
                let template = fs.readFileSync('./templates/main.mustache').toString('UTF-8');
                res.writeHead(200, { 'Content-Type': 'text/html' });

                res.end(mustache.render(template, {
                    username: username,
                    users: results[0],
                    squeaks: results[1],
                    squeals: results[2]
                }))
            });
    }
});

app.post('/signin', async (req, res) => {
    let signin = false;
    let credentials = req.body;
    let username = credentials['username'].toString();
    let password = credentials['password'].toString();
    let validUsername = username !== undefined && username.length >= 4;
    let validPassword = password !== undefined && password.length >= 8 && password.length <= 25;

    let re = new RegExp('^[A-Za-z0-9 .!,_\']*$')
    if (!re.test(username)) validUsername = false;

    if (validUsername && validPassword) {
        try {
            password = crypto.pbkdf2Sync(password, 'secret', 10000, 64, 'sha512').toString('hex');
        } catch (err) {
            res.json(signin)
            return;
        }
        await authenticate(username, password)
            .then((user) => {
                if (user) {
                    signin = true;
                    return newSession()
                }
            }).then(async (sessionid) => {
                if (signin) {
                    let signusername = crypto.sign('SHA256', credentials['username'], privateKey).toString('base64')
                    res.cookie('squeak-session',
                        JSON.stringify({
                            sessionid: sessionid,
                            username: signusername
                        }),
                        {
                            expire: getExpirationTimeCookie(),
                            httpOnly: true,
                            secure: true
                        }
                    );
                }
                res.json(signin)
            }).catch((error) => {
                console.log(error);
            })
    } else res.json(signin)
});

app.post('/signup', async (req, res) => {
    let credentials = req.body;
    let username = credentials['username'].toString();
    let password = credentials['password'].toString();
    let validUsername = username !== undefined && username.length >= 4;
    let validPassword = password !== undefined && password.length >= 8 && password.length <= 25;

    let re = new RegExp('^[A-Za-z0-9 .!,_\']*$')
    if (!re.test(username)) validUsername = false;

    await authenticateUsername(username)
        .then((user) => {
            if (user) validUsername = false; //username already exists

            if (!validUsername) {
                res.json({ reason: 'username' });
                return;
            }

            if (validPassword) {
                let nameregex = new RegExp(username);
                validPassword &= !nameregex.test(password);
            }

            if (!validPassword) {
                res.json({ reason: 'password' });
                return;
            }

            try {
                password = crypto.pbkdf2Sync(password, 'secret', 10000, 64, 'sha512').toString('hex');
            } catch(err) {
                console.log('passss')
                res.json({ reason: 'password' });
                return;
            }

            addUser(username, password)
                .then(() => {
                    return newSession()
                })
                .then((sessionid) => {
                    let signusername = crypto.sign('SHA256', username, privateKey).toString('base64')
                    res.cookie('squeak-session',
                        JSON.stringify({
                            sessionid: sessionid,
                            username: signusername
                        }),
                        {
                            expire: getExpirationTimeCookie(),
                            httpOnly: true,
                            secure: true
                        }
                    );
                    res.json({ success: 'true' })
                })
                .catch((error) => {
                    console.log(error);
                })
        })
});

app.post('/signout', async (req, res) => {
    let cookie = req.cookies;
    if (cookie['squeak-session']) {
        cookie = JSON.parse(cookie['squeak-session'])
        let sessionid = cookie.sessionid;
        await invalidateSession(sessionid).then((session) => {
            res.send(JSON.stringify(true))
        }).catch((error) => {
            console.log(error)
        })
    }
});

app.post('/squeak', async (req, res) => {
    if (req.session) { 
        let body = req.body;
        await addSqueak(req.session['username'], body['recipient'], body['squeak'])
            .then(() => {
                res.writeHead(302, { 'Location': '/' });
                res.end();
            }).catch((error) => {
                consol.log(error)
            })
    } else {
        res.send(JSON.stringify(false))
    }
});

MongoClient.connect(mongoURL)
    .then((cluster) => {
        let db = cluster.db('Squeak!');
        squeaks = db.collection('squeaks');
        credentials = db.collection('credentials');
        sessions = db.collection('sessions');

        let server = https.createServer(options, app);
        server.listen(8000);
    }).catch((error) => {
        let server = https.createServer(options, (req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<h1>Page is currently not working!</h1>');
        });
        server.listen(8000);
        console.log(error);
    })