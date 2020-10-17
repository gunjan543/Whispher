//jshint esversion:6
//for environment variables
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require('express-session');
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy=require('passport-google-oauth20').Strategy;
const findOrCreate=require('mongoose-findorcreate')

const app=express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
extended:true
}));

//creating/initialize a session,setup a session
app.use(session({
  secret:"Our little secret .",
  resave:false,
  saveUninitialized:false
}));
//initialize passport
app.use(passport.initialize());
//ask passport to set up our session
app.use(passport.session());

//connect mongo
mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true});
//to remove deprecation warning
mongoose.set("useCreateIndex",true);
//create javascript schema
//change schema to mongoose schema because of encryption standards
const userSchema=new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

//add plugin to hash and salt passwords and to save users to mongodb
userSchema.plugin(passportLocalMongoose);
//add OAuth plugin
userSchema.plugin(findOrCreate);

//mongoose model
const User = new mongoose.model("User",userSchema);

//setup local strategy
passport.use(User.createStrategy());
//serialise and deseralise sessions used when using sessions
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//oauth20
passport.use(new GoogleStrategy({
    clientID: process.env.client_ID,
    clientSecret:process.env.client_secret,
    callbackURL: "http://localhost:3000/auth/google/whispher",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res) {
  res.render("home");
});

//get request for auth by google
app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));
app.get("/login",function(req,res) {
  res.render("login");
});

app.get("/auth/google/whispher",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/register",function(req,res) {
  res.render("register");
});

app.get("/secrets",function (req,res) {
 User.find({"secret":{$ne:null}},function(err,foundUsers) {
  if(err){
    console.log(err);
  } else{
    if(foundUsers){
      res.render("secrets",{userWithSecrets:foundUsers});
    }
  }
 })
});

app.get("/submit",function (req,res) {
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.post("/submit",function (req,res) {
  const submittedSecret=req.body.secret;
  User.findById(req.user.id,function(err,foundUser) {
    if(err){
      console.log(err);
    }
    else {
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });

});

app.get("/logout",function(req,res) {
  req.logout();
  res.redirect("/");
});

app.post("/register",function (req,res) {
  //javascript object
  //register fxn comes from passportLocalMongoose
  User.register({username:req.body.username},req.body.password,function(err,user) {
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login",function(req,res) {

//creating new user
  const user=new User({
    username: req.body.username,
    password:req.body.password
  });
  //used passport to login and authenticate the user
  req.login(user,function (err) {
    if(err){
      console.log(err);
    }
    else{
      passport.authenticate("local")(req,res,function() {
        res.redirect("/secrets");
      });
    }
  });
});


app.listen(3000,function() {
  console.log("Server started on port 3000");
});
