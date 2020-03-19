const express= require("express");
const router= express.Router();
const bcrpt= require("bcryptjs");
const jwt= require("jsonwebtoken");
const keys= require("../../config/keys");

const validateInputRegister= require("../../validation/register");
const validateInputLogin= require('../../validation/login');
const User= require("../../model/User");

router.post("/register", (request, response)=>{
    //Form validation
    const{errors, isValid}= validateInputRegister(request.body)

    if(!isValid){
        return response.status(400).json(errors)
    }
    User.findOne({email:request.body.email}).then(returnedEmail=>{
        if(returnedEmail){
            return response.status(400).json({email:"Email already exists!!!"});
        }
    });

   // saving the user information to database
   const newUser= new User({
       name: request.body.name,
       email: request.body.email,
       password: request.body.password
   });


    bcrpt.genSalt(10, (err, salt)=>{
        bcrpt.hash(newUser.password, salt, (err,hash)=>{
            if(err) throw err;
        newUser.password=hash;
        newUser
        .save()
        .then(user=>response.json(user))
        .catch(err=>console.log(err));
        });       
    }); 
});

router.post("/login", (request, response)=>{
    const {errors, isValid}= validateInputLogin(request.body);
    if(!isValid){
        return response.status(400).json(errors);
    }
    const email= request.body.email;
    const password= request.body.password;
    User.findOne({email:email}).then(user=>{
        if(!user){
            return response.status(400).json({emailnotfound: "Email not found"});
        }
        bcrpt.compare(password, user.password).then(isMatch=>{
            if(isMatch){
                const payload= {id: user.id, name:user.name};
                jwt.sign(payload, keys.secretOrKey, {expiresIn: 31556923}, (err, token)=>{response.json({success:true, token:"Bearer"+token});
            });
            }
            else{
                return response.status(400).json({passwordincorrect:"Password is incorrect"});
            }
        });
    }); 
});

module.exports= router;