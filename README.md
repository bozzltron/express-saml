express-saml
============

SAML authentication support of node.js express framework


Usage:

Add this to server.js

// Routes
require('saml')(app, db);


Now you can secure your site like this: *Note : I am using express framework

  function secure(req,res,next){
        
    // Check session
    if(req.session.currentUser){
      next();
    }else{
      app.settings.saml.startAuth(res);
    }
  }
  
  app.all('/', secure);
