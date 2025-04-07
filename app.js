const path = require("node:path");
const {Pool} = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const pool = new Pool({
    
})

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
    res.render("index", {user: req.user});
    });
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
    try{
        await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [req.body.username, req.body.password]);
        res.redirect("/");
    }catch(err){
        console.log(err);
        return next(err);
    }
})

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
)

passport.use(
    new LocalStrategy( async (username, password, done) => {
        try{
            const {rows} = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
            const user = rows[0];
            if(!user){
                done(null, false, {message: "Incorrect username"})
            }
            if(user.password !== password){
                done(null, false, {message: "Incorrect password"})
            }
            return done(null, user)
        } catch(err){
            return done(err);
        }
    })
)

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser( async (id, done) => {
    try{
        const {rows} = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
        const user = rows[0];
        done(null, user);
    }catch(err){
        done(err);
    }
})

app.listen(3000, () => console.log("app listening on port 3000!"));