//require router, model
const router = require('express').Router()
const bcrypt = require('bcryptjs');
const { response } = require('../app');
const UserModel = require('../models/User.model')

let userInfo = {}

//signup
router.get('/signup', (req, res, next)=>{
 res.render('auth/signup.hbs')
})

//signin
router.get('/signin', (req, res, next)=>{
 res.render('auth/signin.hbs')
})

//Handle posts 
router.post('/signup',(req, res, next)=>{
   const {username, password} = req.body

 //to check for unique usernames
    if(!username.unique){
    res.render('auth/signup.hbs', {msg: 'The username can\'t be repeated'})
     return
   }

   if(!username || !password){

    res.render('auth/signup.hbs', {msg: 'The fields can\'t be empty'})

    return
   }
     //Validate Password: 
     const passRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/
     if (!passRe.test(password)) {
       res.render('auth/signup.hbs', {msg: 'Password must be 8 characters, must have a number, and an uppercase Letter'})
   
       return;
     }

     const salt = bcrypt.genSaltSync(12);
     const hash = bcrypt.hashSync(password, salt);

   UserModel.create({username, password: hash})
   .then(() => {
       res.redirect('/')
   }).catch((err) => {
      
       next('Beautiful error message') 
   });

})

router.post('/signin', (req, res, next)=>{
    const {username, password} = req.body

  UserModel.findOne({username})
  .then((response) => {
      if(!response){
          res.render('auth/signin.hbs',{msg: 'Username or password seems to be incorrect'})
      }
      else{
        bcrypt.compare(password, response.password) 
        .then((isMatching) => {
           if(isMatching){
            
            req.session.userInfo = response
            res.redirect(`/profile`)
           }else{
               res.render('auth/signin.hbs',{msg: 'Username or password seems to be incorrect'})
           }
 
         })
        
     }
     
    })
     .catch((err) => {
        next(err) 
      })
})

 //CUSTOM Middlewares functions
 const authorize = (req, res, next) => {
   
    if (req.session.userInfo) {
      next()
    }
    else {
      res.redirect('/signin')
    }
    
  }


router.get('/profile', authorize, (req, res, next) => {
     
    const {username} = req.session.userInfo 
     res.render('profile.hbs', {username})
 })


router.get('/main', authorize,  (req, res, next) => {
   
     res.render('main.hbs')
 })

router.get('/private', authorize, (req, res, next) => {
   
     res.render('private.hbs')
 })
  




module.exports = router;


