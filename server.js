const express = require('express'); // Express framework
const app = express(); // Therrasim aplikacionin
require("dotenv").config(); // moduli per dotenv file ku ruhet PORT dhe DB_URL 
const passport = require('passport'); // moduli per menagjimin e login register page
const LocalStrategy = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');
const bodyParser = require('body-parser'); // Moduli per trajtimin e req res nga ejs body
const session = require('express-session');
const User = require('./model/User'); // schema user
const File = require('./model/File'); // schema file
// const auth = require('./auth/auth');-
const mongoose = require('mongoose'); // Moduli per lidhjen me databaze
const path = require('path'); // Moduli per njohejen e pathit
const multer = require('multer'); // Mo duli per upload file nga formi dhe trajtimi i serverside
const bcrypt = require('bcrypt'); // Moduli per enkryptimin e passwordave ne mongodb
const fs = require('fs'); // File System modul
const { v4: uuidv4 } = require('uuid'); // ID modul
//const ClamScan = require('clamscan'); // Scanimin e vriuseve gjate upload te aplikacioneve 
//const clamscan = new ClamScan();
const Publishable_Key = process.env.stripe // edhe ktu
const Secret_Key = process.env.stripe2 // ni key vyn 
const stripe = require('stripe')(Secret_Key); // moduli per zhvillimin e payment method
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Configuration, OpenAIApi } = require('openai');
const {Client, Config, CheckoutAPI} = require('@adyen/api-library');
//const nodemailer = require('nodemailer');
const useragent = require('useragent');
const geoip = require('geoip-lite'); // location data
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Middleware configuration 
app.use(session({
    secret: 'ymySuperSecretKeyThatIsLongAndRandom123!@#$', // per auth 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));
app.use(passport.initialize());
app.use(cors())
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    } else {
        res.redirect('/login');
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Main URL
const mainURL = 'http://localhost:8801';
//const mainURL = req.protocol + '://' + req.get('host');

// Template te bootstrap dhe jquery
//app.use(express.static(path.join(__dirname, 'assets', 'style')));
//npapp.use(express.static(path.join(__dirname, 'vendor', 'vendor')));

// Template engine setup (EJS)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('img'));
const uploadPath = path.join(__dirname, 'img');
app.use(express.urlencoded({ extended: true }));
//app.use(express.static(path.join(__dirname, 'modelai')));

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Route middleware
app.use(function (req, res, next) {
    req.mainURL = mainURL;
    req.isLogin = (typeof req.session !== 'undefined' && typeof req.session.user !== 'undefined');
    req.user = req.session.user || null;
    next();
});


// Home page
// http:localhost:8000/
app.get('/', function (req, res) {
    res.render('index');
});

// File generator
// http:localhost:8000/fileGenerator
app.get('/fileGenerator', function (req,res) {
    res.render('fileGenerator')
})

// ChatAI page
// http:localhost:8000/chatAi
app.get('/chatAi', function (req, res) {
    res.render('chatAi');
});

// robot page
// http:localhost:8000/chatAi
//app.get('/robotAi', function (req, res) {
//    res.render('robotAi');
//});

// speech test page
// http:localhost:8000/speech
app.get('/spech', function (req, res) {
    res.render('spech');
});


// FuncCloud page
// http:localhost:8000/funcCloud
app.get('/funcCloud', function  (req, res) {
    res.render('funcCloud', { username: req.session.username });
});


//app.get('/virus', function (req, res) {
//    res.render('virus');
//});


// ucfmChatBot page
// http:localhost:8000/chatbot
//app.get('/chatbot', function (req, res) {
//    res.render('chatbot');
//});

// func2.ejs page
app.get('/func2', function (req, res) {
    res.render('func2.ejs'); // main/
});

    
// video Cloud page
// http:localhost:8000/video-cl 
app.get('/video-cl', function (req, res) {
    res.render('video-cl');
});

// video account page
// http:localhost:8000/video-ac
app.get('/video-ac', function (req, res) {
    res.render('video-ac');
});

// video fileshare page
// http:localhost:8000/video-fl
app.get('/video-fl', function (req, res) {
    res.render('video-fl');
});

// video premium page
// http:localhost:8000/video-fl
app.get('/vd-premium', function (req, res) {
    res.render('vd-premium');
});

// Fileshare page
// http:localhost:8000/fileshare
app.get('/fileshare/:id', function (req, res) {
    res.render('fileshare');
});

// app page
// http:localhost:8800/app
app.get('/app', function (req, res) {
    res.render('app')
})

// Video Page
// http:localhost:8000/video
app.get('/video', function (req, res) {
    res.render('video')
})

// Secret page
// http:localhost:8000/secret
app.get('/secret', function (req, res) {
   res.render('secret', { username: req.session.username });
});

// Middleware for authenticated users
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/funcCloud');
        }

        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});


// Register page
// http:localhost:8000/register
app.get('/register', function (req, res) {
    res.render('login.ejs');
});

// Wrongpw page
// http:localhost:8800/wrongpw
app.get('/wrongpw', function (req, res) {
    res.render('wrongpw')
})

// Wrong User not found page
// http:localhost:8800/notfound for users
app.get('/notfound', function (req, res) {
    res.render('notfound');
})

// email is used
// http:localhost:8800/emailuse
app.get('emailuse', function (req, res) {
    res.render('emailuse')
})

// Premium 16 gb 
// http:localhost:8800/16gb
app.get('/16gb', function (req, res) {
    res.render('16gb')
})

// Premium 32 gb 
// http:localhost:8800/32gb
app.get('/32gb', function (req, res) {
    res.render('32gb')
})

// Premium 64 gb 
// http:localhost:8800/64gb
app.get('/64gb', function (req, res) {
    res.render('64gb')
})

// Premium 128 gb 
// http:localhost:8800/32gb
app.get('/128gb', function (req, res) {
    res.render('128gb')
})

// Premium 256 gb 
// http:localhost:8800/256gb
app.get('/256gb', function (req, res) {
    res.render('256gb')
})

// Premium 514 gb 
// http:localhost:8800/514gb
app.get('/514gb', function (req, res) {
    res.render('514gb')
})

// UCFM ai
// http:localhost:8800/ucfmAi
app.get('/ucfmAi', function (req, res) {
    res.render('ucfmAi')
})

// Premium page
// http:localhost:8800/premium
app.get('/premium', function (req, res) {
    res.render('premium')
})

// Instruction Page
// http:localhost:8000/ins

app.get('/suport', function (req, res) {
    res.render('suport');
});

/*
// Support Page
// http:localhost:8000/suport
app.get('/support', function (req, res) {
    res.render('suport.ejs');
})*/

// Login page
// http:localhost:8000/login
app.get('/login', function (req, res) {
    res.render('login.ejs');
});


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Me marr foto nga Face Detection AI 
app.use(bodyParser.json({ limit: '50mb' }));

mongoose.connect(process.env.DB_URL, { useNewUrlParser: true, useUnifiedTopology: true })

// Nje skem per userat
const imageSchema = new mongoose.Schema({
    path: String,
    dateSaved: { type: Date, default: Date.now },
    status: String
});

const Image = mongoose.model('userimage/verified', imageSchema);

app.post('/save-image', (req, res) => {
    const imgData = req.body.image.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(imgData, 'base64');
    const imgPath = path.join(__dirname, 'PhotoUser', `ucfm-user-image${Date.now()}.jpg`);

    fs.writeFile(imgPath, buffer, (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Failed to save image');
        }

        // 
        const newImage = new Image({
            path: imgPath,
            status: 'Image saved / User is Verified',
        });

        newImage.save()
            .then(() => res.send('Image saved and record added to DB'))
            .catch(dbErr => {
                console.error(dbErr);
                res.status(500).send('Failed to save image to DB');
            });
    });
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pay for 16gb 
app.get('/premium', function(req, res){
    res.render('premium', {
       key: Publishable_Key
    })
})
 
app.post('/paguj1', function(req, res){
 
    stripe.customers.create({
        email: req.body.stripeEmail,
        source: req.body.stripeToken,
        name: 'Idriz Mirena',
        address: {
            postal_code: '12000',
            city: 'Pristina',
            state: 'Kosovo',
            country: 'Kosovo',
        }
    })
    .then((customer) => {
 
        return stripe.charges.create({
            amount: 30,    // price
            description: 'UCFM package',
            currency: 'EUR',
            customer: customer.id
        });
    })
    .then((charge) => {
        res.render('16gb')  // nese pagesa kryhet
    })
    .catch((err) => {
        res.status(500);       // nese ndodh naj errror
    });
})

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pay for 32gb 
app.post('/paguj2', function(req, res){
 
    stripe.customers.create({
        email: req.body.stripeEmail,
        source: req.body.stripeToken,
        name: 'Idriz Mirena',
        address: {
            postal_code: '12000',
            city: 'Pristina',
            state: 'Kosovo',
            country: 'Kosovo',
        }
    })
    .then((customer) => {
 
        return stripe.charges.create({
            amount: 60,    // price
            description: 'UCFM package',
            currency: 'EUR',
            customer: customer.id
        });
    })
    .then((charge) => {
        res.render('32gb')  // nese pagesa kryhet
    })
    .catch((err) => {
        res.status(500); // nese ndodh naj errror
    });
})


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pay for 64gb 
 
app.post('/paguj3', function(req, res){
 
    stripe.customers.create({
        email: req.body.stripeEmail,
        source: req.body.stripeToken,
        name: 'Idriz Mirena',
        address: {
            postal_code: '12000',
            city: 'Pristina',
            state: 'Kosovo',
            country: 'Kosovo',
        }
    })
    .then((customer) => {
 
        return stripe.charges.create({
            amount: 90,    // price
            description: 'UCFM package',
            currency: 'EUR',
            customer: customer.id
        });
    })
    .then((charge) => {
        res.render('64gb')  // nese pagesa kryhet
    })
    .catch((err) => {
        res.status(500); // nese ndodh naj errror
    });
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pay for 128gb 
 
app.post('/paguj4', function(req, res){
 
    stripe.customers.create({
        email: req.body.stripeEmail,
        source: req.body.stripeToken,
        name: 'Idriz Mirena',
        address: {
            postal_code: '12000',
            city: 'Pristina',
            state: 'Kosovo',
            country: 'Kosovo',
        }
    })
    .then((customer) => {
 
        return stripe.charges.create({
            amount: 120,    // price
            description: 'UCFM package',
            currency: 'EUR',
            customer: customer.id
        });
    })
    .then((charge) => {
        res.render('16gb')  // nese pagesa kryhet
    })
    .catch((err) => {
        res.status(500); // nese ndodh naj errror
    });
})


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pay for 256gb 
 
app.post('/paguj5', function(req, res){
 
    stripe.customers.create({
        email: req.body.stripeEmail,
        source: req.body.stripeToken,
        name: 'Idriz Mirena',
        address: {
            postal_code: '12000',
            city: 'Pristina',
            state: 'Kosovo',
            country: 'Kosovo',
        }
    })
    .then((customer) => {
 
        return stripe.charges.create({
            amount: 130,    // price
            description: 'UCFM package',
            currency: 'EUR',
            customer: customer.id
        });
    })
    .then((charge) => {
        res.render('256gb')  // nese pagesa kryhet
    })
    .catch((err) => {
        res.status(500); // nese ndodh naj errror
    });
})

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pay for 514gb 
 
app.post('/paguj6', function(req, res){
 
    stripe.customers.create({
        email: req.body.stripeEmail,
        source: req.body.stripeToken,
        name: 'Idriz Mirena',
        address: {
            postal_code: '12000',
            city: 'Pristina',
            state: 'Kosovo',
            country: 'Kosovo',
        }
    })
    .then((customer) => {
 
        return stripe.charges.create({
            amount: 160,    // price
            description: 'UCFM package',
            currency: 'EUR',
            customer: customer.id
        });
    })
    .then((charge) => {
        res.render('514gb')  // nese pagesa kryhet
    })
    .catch((err) => {
        res.status(500); // nese ndodh naj errror
    });
})


// Func Cloud Upload 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.use(bodyParser.json({ limit: '50mb' }));

// lidhaj me db
mongoose.connect(process.env.DB_URL , { useNewUrlParser: true, useUnifiedTopology: true })

// schema per image shcema upload
const imageSchemaUpload = new mongoose.Schema({
    path: String,
    originalName: String,
    dateSaved: { type: Date, default: Date.now },
    status: String
});

const Image2 = mongoose.model('cloudstorage', imageSchema);

// Konfigurimi i multer per storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'CloudStorage');
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const uploadC = multer({ storage: storage });

// Sherben faqen kryesore
app.get('/funcCloud', (req, res) => {
    res.sendFile(path.join(__dirname, 'funcCloud')); // dir
});

// Per trajtimin e ngarkimi
app.post('/up', uploadC.array('files'), (req, res) => {
    const uploadedFiles = req.files || [];

    const filePromises = uploadedFiles.map(file => {
        const newImage = new Image2({
            path: file.path,
            originalName: file.originalname,
            status: 'Image saved'
        });

        return newImage.save();
    });

    Promise.all(filePromises)
        .then(() => {
            res.send(`<script>showUploadedFiles(${JSON.stringify(uploadedFiles)})</script>`);
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('Failed to save image to DB');
        });
});


// app page cloud 2
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const storage2 = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'AppStorage');
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const uppw2 = multer({ storage: storage2 });

// Sherben faqen kryesore
app.get('/app', (req, res) => {
    res.sendFile(path.join(__dirname, 'app'));
});

// perdorimi i multerit mi trajtu files
app.post('/up2', uppw2.array('files'), (req, res) => {
    const uploadedFiles = req.files || [];
    res.send(`<script>showUploadedFiles(${JSON.stringify(uploadedFiles)})</script>`);
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File Share
app.use(express.urlencoded({ extended: true }))
const upload = multer({ dest: "pwfileUploads" })

mongoose.connect(process.env.DB_URL) // Lidhja me db me filepw te enkryptuar

// http:localhost:8000/fileshare == > ku kryhet veprimi i funksioneve te file Share
app.get("/", (req, res) => {
    res.render("fileshare")
})

// Post method ku pranohet file dhe kontrollohet per fjalkalim, dhe gjeneron nje link
app.post("/upload", upload.single("file"), async (req, res) => {
    const fileData = {
        path: req.file.path,
        originalName: req.file.originalname,
    }
    if (req.body.password != null && req.body.password !== "") {
        fileData.password = await bcrypt.hash(req.body.password, 10)
    }

    const file = await File.create(fileData)

    res.render("fileshare", { fileLink: `${req.headers.origin}/file/${file.id}` })
})

// emertimi i route te file ng aid
app.route("/file/:id").get(handleDownload).post(handleDownload)

async function handleDownload(req, res) {
    const file = await File.findById(req.params.id)

    if (file.password != null) {
        if (req.body.password == null) {
            res.render("password")
            return
        }

        if (!(await bcrypt.compare(req.body.password, file.password))) {
            res.render("password", { error: true })
            return
        }
    }

    file.downloadCount++
    await file.save()
    console.log(file.downloadCount)

    res.download(file.path, file.originalName)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {

        ..
        ..
    },
});

app.post('/verify', (req, res) => {
    const email = req.body.email;
    const token = crypto.randomBytes(32).toString('hex');
    
    // Save the token and email in your database for later verification

    const mailOptions = {
        from: 'idrizmirenaa@gmail.com',
        to: email,
        subject: 'Confirm your email address',
        text: `Click on this link to verify your email: http://localhost:${process.env.PORT}/verify?token=${token}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            res.status(500).send('Error sending verification email.');
        } else {
            console.log('Email sent: ' + info.response);
            res.send('Verification email sent.');
        }
    });
});
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Funksion per me marr data lloji i device
function getDeviceType(agent) {
    if (agent.device.family.includes('iPhone') || agent.device.family.includes('Android')) {
        return 'Mobile';
    } else if (agent.device.family.includes('iPad') || agent.device.family.includes('Tablet')) {
        return 'Tablet';
    } else if (agent.device.family.includes('hp') || agent.device.family.includes('dell')) {
        return 'Laptop';
    } else {
        return 'Desktop';
    }
}

// Routi per register
app.post('/register', async function (req, res) {
    try {
        const { username, password, email } = req.body;

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.render('emailuse');
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // marrja e data
        const ip = req.ip;
        const agent = useragent.parse(req.headers['user-agent']);
        const browser = agent.toAgent();
        const os = agent.os.toString();
        const device = getDeviceType(agent);
        const geo = geoip.lookup(ip);

        const location = {
            country: geo ? geo.country : 'Unknown',
            city: geo ? geo.city : 'Unknown'
        };

        const user = new User({
            username,
            password: hashedPassword,
            email,
            registration: { ip, browser, os, device, location, timestamp: new Date() }
        });

        await user.save();

        res.redirect('/login');
    } catch (error) {
        res.status(400).json({ error });
    }
});

// route per login
app.post('/login', async function (req, res) {
    try {
        const user = await User.findOne({ username: req.body.username });

        if (user) {
            const passwordMatch = await bcrypt.compare(req.body.password, user.password);

            req.session.userId = user._id;
            // nalu
            if (passwordMatch) {
                //me marr data
                const ip = req.ip;
                const agent = useragent.parse(req.headers['user-agent']);
                const browser = agent.toAgent();
                const os = agent.os.toString();
                const device = getDeviceType(agent);
                const geo = geoip.lookup(ip);

                const location = {
                    country: geo ? geo.country : 'Unknown',
                    city: geo ? geo.city : 'Unknown'
                };

                // Informacionen e fundi gjithe bohen update
                user.lastLogin = { ip, browser, os, device, location, timestamp: new Date() };
                await user.save();

                res.render('secret', { username: user.username });
            } else {
                res.render('wrongpw');
            }
        } else {
            res.render('notfound');
        }
    } catch (error) {
        res.status(400).json({ error });
    }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Video 1
///////////////////////////////////////////////////////////////////////////

app.get('/suport', (req, res) => {
    res.sendFile(__dirname + '/suport');
})

app.get('/videoplayer1', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/video1.mp4'; // video premium
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})


app.get('/suport', (req, res) => {
    res.sendFile(__dirname + '/suport');
})

app.get('/videoplayer2', (req, res) => {
    const range = req.headers.range;
    const videoPath = './Videos/video2.mp4';
    const videoSize = fs.statSync(videoPath).size;
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""));
    const end = Math.min(start + chunkSize, videoSize - 1);
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    };
    res.writeHead(206, headers);
    const stream = fs.createReadStream(videoPath, { start, end });
    stream.pipe(res);
});




app.get('/suport', (req, res) => {
    res.sendFile(__dirname + '/suport');
})

app.get('/videoplayer3', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/video3.mp4'; // video premium
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})


app.get('/suport', (req, res) => {
    res.sendFile(__dirname + '/suport');
})

app.get('/videoplayer4', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/video4.mp4'; // video premium
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})


app.get('/suport', (req, res) => {
    res.sendFile(__dirname + '/suport');
})

app.get('/videoplayer5', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/video5.mp4'; // video premium
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})


app.get('/suport', (req, res) => {
    res.sendFile(__dirname + '/suport');
})

app.get('/videoplayer6', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/video6.mp4'; // video premium
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})

// Video 3
/*
app.get('/video-ac', (req, res) => {
    res.sendFile(__dirname + '/video-ac');
})

app.get('/videoplayer3', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/acc.mp4';
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})*/

// Video 4 

app.get('/vd-premium', (req, res) => {
    res.sendFile(__dirname + '/vd-premium');
})

app.get('/videoplayer-premium', (req, res) => {
    const range = req.headers.range
    const videoPath = './Videos/rruga.mp4'; // video premium
    const videoSize = fs.statSync(videoPath).size
    const chunkSize = 1 * 1e6;
    const start = Number(range.replace(/\D/g, ""))
    const end = Math.min(start + chunkSize, videoSize - 1)
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers)
    const stream = fs.createReadStream(videoPath, {
        start,
        end
    })
    stream.pipe(res)
})


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Logout route
app.get('/logout', function (req, res) {
    req.logout(function (err) {
        if (err) return next(err);
        res.redirect('/');
    });
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Server port
const PORT = process.env.PORT || 3000;

// Start the server
app.listen(PORT, function () {
    console.log(`Server started on port http://localhost:${PORT}`);

    const lidhjaMedb = () => {
        mongoose
            .connect(process.env.DB_URL, {
                useUnifiedTopology: true,
                useNewUrlParser: true,
            })
            .then(() => {
                console.log('Databaza nga llogarit eshte lidhur');
            })
            .catch((err) => {
                console.log(`Database error: ${err}`);
            });
    };
    lidhjaMedb();
});


