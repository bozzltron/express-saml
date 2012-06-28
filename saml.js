// Define SAML routes

function routes(app, db) {
    
  // Receive the SAML Response here
  app.post('/saml/consume', function(req, res){
    
    var libxmljs = require("libxmljs");
    
    // Get SAML response
    var samlResponse = req.body.SAMLResponse;
    
    // Decode response
    var xml = new Buffer(samlResponse, 'base64').toString('ascii');
    
    // Parse ID
    var xmlDoc = libxmljs.parseXmlString(xml);
    var idNode = xmlDoc.get('/samlp:Response/saml:Assertion/saml:Subject/saml:NameID', {
      'samlp':'urn:oasis:names:tc:SAML:2.0:protocol',
      'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion'
    });
    
    var email = idNode.text();
    
    // User lookup
    app.settings.models.User.findOne({email:email}, function(err, user){
      
      if (user) {
          
        // Grant session
        req.session.currentUser = user;
        req.flash('info', 'You are logged in as ' + email);
        res.redirect('/');
        return;
      } else {
          
        // Redirect
        req.flash('error', 'Your account did not match any of our records.');
        res.redirect('/login');
        return;
      }
    });    
    
  });
  

  // Use this psuedo class to initiate the SAML Request
  var SAML = {
    
    // Initiate SAML authentication
    startAuth: function(res) {
        
      // Generate a unique ID
      var chars = "abcdef0123456789";
      var chars_len = chars.length;
      var uniqueID = "";
      for (var i = 0; i < 20; i++) {
         uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
      }
   
      var id = "_" + uniqueID;
 
      var date = new Date();
      
      // Setup SAML request
      var issue_instant = date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours()+2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
      var http = "http://";
      var https = "https://";
      var const_assertion_consumer_service_url = https + req.headers.host + '/saml/consume';  // Post auth destination
      var const_issuer = "onelogin_saml";
      var const_name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
      var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + issue_instant + "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + const_assertion_consumer_service_url + "\">" +
         "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + const_issuer + "</saml:Issuer>\n" +
         "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + const_name_identifier_format + "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n" +
         "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
         "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
         "</samlp:AuthnRequest>";
         
      var zlib = require('zlib');

      // Encode with deflate
      zlib.deflateRaw(request, function(err, buffer) {
        if (!err) {
          
          var deflated_request = buffer;
              
          // Base64 encode
          var base64_request   = deflated_request.toString('base64');
    
          // URI encode
          var encoded_request  = encodeURIComponent(base64_request);
          
          // Get api key
          db.collection('variables', function(err, collection){
            collection.findOne({name:'onelogin'}, function(err, doc){
              
              var path = doc.saml + "?SAMLRequest=" + encoded_request;
              res.redirect(path);
              
            });    
          });          
          
        }
      });

    }
  
  };
  
  app.get('/saml/start', function(req,res){
    SAML.startAuth(res);
  });  
  
  app.set('saml', SAML);
  
} 

module.exports = routes;
