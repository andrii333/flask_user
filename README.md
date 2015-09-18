# Flask User
Lib for log-in in Flask

Designated to write to COOKIE:
    STAT info about user (last_visit timestamp, kolvo_visits, his language etc...all that is nned for analysis and user personalization)
    LOG_TOKEN - log IN token
    
STAT and LOG_TOKEN - have signature.

IN cookie it remains as:
    stat={....}
    stat_signature='signature'  //using itsdangerous
    
    log_token='json string in base64.token'
    
The main logic is next:

@app.before_request
def before_request():
    app.user = User()  //it must be once, to put object in app.dictionary
    app.user.deserialize(request)   //pull from request cookie and from request.environ['SERVER_NAME']
    
$app.after_request
def after_request():
    app.user_serialize(response)  //it put into cookies stat, stat_signature and if it is - log_token 
    
If you need to use login, you can use it in next way:
app.user.check_auth()  - returns True if it is, false if no....so it is only checking
app.user.login(user_name,user_pass)  //cretes new session dictionary and generate new log_token
app.user.roles  - contains list with user roles
app.user.registration(name,pass....)


    
