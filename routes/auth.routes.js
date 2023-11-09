const { Router } = require('express'); //Router is part of EXPRESS
const router = new Router();
const User = require("../models/User.model")

const bcrypt = require('bcryptjs');
const saltRounds = 5;

router.get('/signup', (req, res) => {
    res.render('auth/signup')
})

router.get('/profilePage', (req, res) =>{
    res.render('profilePage')
})

router.post('/signup', (req, res, next) => {
    const { username, password } = req.body
    bcrypt.genSalt(saltRounds)
        .then(salt => bcrypt.hash(password, salt))
        .then((hashedPassword) => {
            //console.log({ hashedPassword });
            User.create({
                username,
                password: hashedPassword
            })
            
        })
        .then((userCreated) => {
            res.redirect('./profilePage')
        })

        //Since this validation is part of mongoose,
        // we will have to use mongoose to retrieve the message.
        .catch(error => {
            // copy the following if-else statement
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', { errorMessage: error.message });
            } else {
                next(error);
            }
          })                                    //next(error) //goes to the next middleware

})

module.exports = router;