var express  = require('express');
var app      = express();
var http     = require('http').Server(app);
var port     = process.env.PORT || 3000;

var mongoose = require('mongoose');
var passport = require('passport');
var flash 	 = require('connect-flash');

var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');

var configDB = require('./config/database.js');

mongoose.connect(configDB.url);

require('./config/passport')(passport); // pass passport for configuration

app.use(morgan('dev'));
app.use(cookieParser());
app.use(bodyParser());

app.set('view engine', 'ejs');

// required for passport
app.use(session({secret: 'secret'}));
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

require('./app/routes.js')(app, passport); // load our routes and pass in our app and fully configured passport

http.listen(port, function(){
	console.log('In port 3000');
});