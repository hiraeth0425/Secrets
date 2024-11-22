import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import cors from "cors"

const app = express();
const port = process.env.PORT || 8000;
const saltRounds = 10;

env.config();

//CORS 配置
app.use(cors({
  origin: ['https://secrets-demo.onrender.com', 'http://localhost:8000', 'http://localhost:8080'],
  credentials: true, // 重要：允許跨域攜帶 cookie
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json()); //// 解析 JSON 請求體
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // HTTPS 環境
      maxAge: 24 * 60 * 60 * 1000, // 24小時
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

const connectionString = process.env.DATABASE_URL

const db = new pg.Client({
  connectionString: connectionString,
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT || 5432,
  ssl: {
    rejectUnauthorized: false
  }
});

db.connect()
  .then(() => {
    console.log('Database Connection Details:');
    console.log('Host:', process.env.PG_HOST);
    console.log('Port:', process.env.PG_PORT);
    console.log('Database:', process.env.PG_DATABASE);
    console.log('User:', process.env.PG_USER);
    console.log('Password Length:', process.env.PG_PASSWORD.length);
  })
  .catch(err => {
    console.error('Database Connection Error:', err);
    console.error('Error Details:', {
      host: process.env.PG_HOST,
      port: process.env.PG_PORT,
      database: process.env.PG_DATABASE,
      user: process.env.PG_USER
    });
  });

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    return res.redirect("/");
  });
});

app.get("/secrets", async(req, res) => {
   // 添加更多日誌來追蹤執行流程
   console.log("Accessing secrets route");
   console.log("Session:", req.session);
   console.log("User:", req.user);
   console.log("isAuthenticated:", req.isAuthenticated());

  if(req.isAuthenticated()){
    try{
      const result = await db.query("SELECT * FROM users WHERE username = $1", [req.user.username])
      const user = result.rows[0]
      console.log("Database query result:", result.rows);
      if(user.secret){
        res.render("secrets.ejs",{
          secret: user.secret || 'No Secret',
        })
      }else {
        res.render("secrets.ejs",{
          secret: 'No Secret'
        })
      }
    }catch(err){
      console.error("Database error:", err);
      return res.status(500).send("An error occurred");
    }
  }else{
    console.log("User not authenticated, redirecting to login");
    return res.redirect("/login")
  }
});

//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.
app.get("/submit",(req, res) => {
  if(req.isAuthenticated()){
    res.render("submit.ejs")
  }else{
    return res.redirect("/login")
  }
})

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  // 添加請求內容日誌
  console.log("Registration Request:", {
    body: req.body,
    headers: req.headers,
    method: req.method
  });

  const email = req.body.username;
  const password = req.body.password;

  try {
    // 驗證輸入值
    if (!email || email.trim() === '') {
      return res.status(400).json({
        success: false,
        message: "email is required and cannot be empty"
      });
    }
     // 檢查資料庫連接
     const testConnection = await db.query('SELECT NOW()');
     console.log("Database connection test:", testConnection.rows[0]);

    const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      return res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            return res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
     console.error("Registration error:", {
      error: err,
      stack: err.stack,
      body: req.body
    });
    res.status(500).json({
      success: false,
      message: "Registration failed",
      error: err.message
    });
  }
});

//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit",async(req, res) => {
  try{
    const secret = req.body.secret
    const user = req.user.username    
    console.log(secret);
    const result = await db.query("UPDATE users SET secret = $1 WHERE username = $2 RETURNING *;",[secret, user])
    return res.redirect("/secrets")
  }catch(err){
    console.log(err);
  }
})


passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
        // 檢查資料庫連接
      const testConnection = await db.query('SELECT NOW()');
      console.log("Database connection test:", testConnection.rows[0]);

      const result = await db.query("SELECT * FROM users WHERE username = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false, { message: "Invalid password" });
            }
          }
        });
      } else {
        return cb("User not found")
      }
    } catch (err) {
      console.error("login error:", {
        error: err,
        stack: err.stack,
        body: req.body
      });
      res.status(500).json({
        success: false,
        message: "login failed",
        error: err.message
      });
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE username = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// 路由錯誤攔截
app.use((err, req, res, next) => {
  console.error('Global Error Handler:', err);
  res.status(500).json({
    message: '服務器錯誤',
    error: err.message,
    stack: process.env.NODE_ENV === 'production' ? '🍂' : err.stack
  });
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// 添加錯誤處理
server.on('error', (error) => {
  console.error('Server Error:', error);
});
