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

const app=express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
extended:true
}));

//creating/initialize a session
app.use(session({
  secret:"Our little secret .",
  resave:false,
  saveUninitialized:true,
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
  password:String
});

//add plugin to hash and salt passwords and to save users to mongodb
userSchema.plugin(passportLocalMongoose);

//mongoose model
const User = new mongoose.model("User",userSchema);

//setup local strategy
passport.use(User.createStrategy());
//serialise and deseralise sessions
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/",function(req,res) {
  res.render("home");
});

app.get("/login",function(req,res) {
  res.render("login");
});

app.get("/register",function(req,res) {
  res.render("register");
});

app.get("/secrets",function (req,res) {
  if(req.isAuthenticated()){
    res.render("secrets");
  }
  else{
    res.redirect("/login");
  }
});

app.get("/logout",function(req,res) {
  req.logout();
  res.redirect("/");
});

app.post("/register",function (req,res) {
  //javascript object
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
