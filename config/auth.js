module.exports = {

	'facebookAuth' : {
		'clientID' 		: '230370410351342', // your App ID
		'clientSecret' 	: '892ee2fe524812ca181f67b9b20770f0', // your App Secret
		'callbackURL' 	: 'http://localhost:3000/auth/facebook/callback'
	},

	'twitterAuth' : {
		'consumerKey' 		: 'y1igm0ec1muBchThiOwZTzb9D',
		'consumerSecret' 	: 'ANQOqMhqs5DsYNOXnTVYGU7oufyC2uz3r4g8o4ouIPvXioFuZk',
		'callbackURL' 		: 'http://localhost:8080/auth/twitter/callback'
	},

	'googleAuth' : {
		'clientID' 		: 'your-secret-clientID-here',
		'clientSecret' 	: 'your-client-secret-here',
		'callbackURL' 	: 'http://localhost:8080/auth/google/callback'
	}

}