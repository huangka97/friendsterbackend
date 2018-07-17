"use strict";

var express = require('express');
var path = require('path');
var logger = require('morgan');
var bodyParser = require('body-parser');
var passwords=require("./passwords.hashed.json");

// Express setup
var app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use(logger('dev'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// MONGODB SETUP HERE
var mongoose=require('mongoose');

mongoose.connection.on('connected', function() {
  console.log('Success: connected to MongoDb!');
});
mongoose.connection.on('error', function() {
  console.log('Error connecting to MongoDb. Check MONGODB_URI in env.sh');
  process.exit(1);
});
mongoose.connect(process.env.MONGODB_URI);

var User=mongoose.model('User',{
	username:{
		type:String,
		required:true
	},
	hashedPassword:{
		type:String,
		required:true
	}
})

// SESSION SETUP HERE
var session=require("express-session");
var MongoStore=require("connect-mongo")(session);
app.use(session({
	secret:"your secret is here",
	store: new MongoStore({mongooseConnection:require('mongoose').connection})
}));
var crypto=require("crypto");
function hashPassword(password){
	var hash=crypto.createHash('sha256');
	hash.update(password);
	return hash.digest('hex');
}

// PASSPORT LOCALSTRATEGY HERE
var passport=require("passport");
var LocalStrategy = require('passport-local').Strategy;
passport.use(new LocalStrategy(
	function(username,password,done){
		//console.log(passwords.passwords.length);
		console.log("Entered LocalStrategy");
		console.log(hashPassword(password));
		//console.log(username,password);
		User.findOne({username:username},function(err,user){
			console.log(user.username,user.hashedPassword);
			if(user.hashedPassword===hashPassword(password)){
				done(null,user);
			}else{
				done(null,false);
			}
		})
		
			

}));

// PASSPORT SERIALIZE/DESERIALIZE USER HERE HERE
passport.serializeUser(function(user,done){
	console.log("SERIALIZE", user);
	done(null, user);
})
passport.deserializeUser(function(user,done){
	console.log("DESERIALIZE");
	console.log(user);
	User.findById(user._id,function(error,results){
		if(error){
			console.log("can't find user");
			//res.send(error);
			done(null,false);
		}else{
			console.log("success");
			done(null,user);
		}
	})
})


// PASSPORT MIDDLEWARE HERE
app.use(passport.initialize());
app.use(passport.session());

//  ROUTES HERE
app.get("/",function(req,res){
	console.log("req.session",req.session);
	console.log("req.user",req.user)
	if(!req.user){
		res.redirect("/login");
	}else{
		res.render('index',{
		user:req.user
	});
	}	
})

app.get("/login",function(req,res){
	res.render('login');
})
app.post("/login",passport.authenticate("local",{
	successRedirect:'/',
	failureRedirect:'/login'

}))

app.get("/logout",function(req,res){
	req.logout();
	res.redirect('/');
});

app.get('/signup',function(req,res){
	res.render('signup');
})

app.post('/signup',function(req,res){
	var user= new User({
		username:req.body.username,
		hashedPassword:hashPassword(req.body.password)
	});
	user.save(function(err,results){
		if(err){
			console.log("error",err);
		}else{
			console.log("success");
			res.redirect("/login");
		}
	})
})

module.exports = app;
