const { Router }= require("express");
const router = new Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10
const mongoose = require("mongoose")
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

const User = require("../models/User.model");


router.get("/signup",isLoggedOut, (req,res)=>{

    res.render("../views/auth/signup.hbs")
})

router.post("/signup", (req,res, next)=>{
   const {username, email, password} = req.body
   if (!username | !email | !password) {
    res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
      res
        .status(500)
        .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
      }}

   bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) =>{
        return User.create({
            username,
            email,
            password: hashedPassword
        })
    })
    .then((userFromDb)=>{
        res.redirect("/userProfile")
    })
    .catch(error => {
        if (error instanceof mongoose.Error.ValidationError) {
          res.status(500).render('auth/signup', { errorMessage: error.message });
        } else if (error.code === 11000) {
          res.status(500).render('auth/signup', {
             errorMessage: 'Username and email need to be unique. Either username or email is already used.'
          });
        } else {
          next(error);
        }
      })
});


router.get('/login',isLoggedOut, (req, res) => {
    res.render('../views/auth/login')
});

router.post("/login",(req, res, next)=>{
    console.log('SESSION =====> ', req.session);
    const { email, password } = req.body;

    if (email === '' || password === '') {
        res.render('auth/login', {
          errorMessage: 'Please enter both, email and password to login.'
        });
        return;
      }
     
      User.findOne({ email })
        .then(user => {
          if (!user) {
            res.render('auth/login', { errorMessage: 'Email is not registered. Try with other email.' });
            return;
          } else if (bcryptjs.compareSync(password, user.password)) {
            res.render('users/user-profile', { user });
            req.session.currentUser = user;
            res.redirect('/userProfile');
          } else {
            res.render('auth/login', { errorMessage: 'Incorrect password.' });
          }
        })
        .catch(error => next(error));
    });

    router.post("/logout", isLoggedIn, (req,res)=>{
      req.session.destroy(err => {
        if (err) next(err);
        res.redirect('/');
      })
    });

    router.get('/userProfile',isLoggedIn, (req, res) => {
        res.render('../views/users/user-profile', { userInSession: req.session.currentUser });
      });


module.exports= router