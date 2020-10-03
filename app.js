//jshint esversion:6
//for environment variables
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const app=express();
const mongoose=require("mongoose");
const encrypt = require("mongoose-encryption");

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));
//connect mongo
mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true});
//create javascript schema
//change schema to mongoose schema because of encryption standards
const userSchema=new mongoose.Schema({
  email:String,
  password:String
});
//it will encrypt when we say save and decrypt when we say find
userSchema.plugin( encrypt,{ secret : process.env.SECRET,encryptedFields:['password']});
//mongoose model
const User = new mongoose.model("User",userSchema);

app.get("/",function(req,res) {
  res.render("home");
});

app.get("/login",function(req,res) {
  res.render("login");
});

app.get("/register",function(req,res) {
  res.render("register");
});


app.post("/register",function (req,res) {
  const newUser = new User({
    email:req.body.username,
    password:req.body.password
  });
  newUser.save(function(err) {
    if(err){
      console.log(err);
    }
    else{
      res.render("secrets");
    }
  });
});

app.post("/login",function(req,res) {
  const username=req.body.username;
  const password=req.body.password;

  User.findOne({email:username},function(err,foundUser){
    if(err){
      console.log(err);
    }
    else {
      {
        if(foundUser){
          if(foundUser.password === password){
            res.render("secrets");
          }
        }
      }
    }
  })
});
app.listen(3000,function() {
  console.log("Server started on port 3000");
});
